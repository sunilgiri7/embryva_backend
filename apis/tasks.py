# tasks.py
from apis.email_service import EmailService
from celery import shared_task
from django.utils import timezone
from django.conf import settings

from apis.services.embeddingsMatching import EmbeddingService
from apis.utils import prepare_donor_data_for_embedding, prepare_metadata_for_pinecone
from .models import Donor, Meeting, User
import logging

logger = logging.getLogger(__name__)

@shared_task(bind=True)
def send_meeting_reminder_emails_task(self):
    """
    Celery task to send meeting reminder emails
    Runs every minute to check for meetings that need reminders
    """
    try:
        logger.info("=== MEETING REMINDER CRON JOB STARTED ===")
        current_time = timezone.now()
        logger.info(f"Current time: {current_time}")
        
        reminder_time_start = current_time
        reminder_time_end = current_time + timezone.timedelta(minutes=1)
        
        meetings_needing_reminders = Meeting.objects.filter(
            reminder_email_sent=False,
            status='scheduled',
            scheduled_datetime__gt=current_time + timezone.timedelta(minutes=4),  # More than 4 minutes away
            scheduled_datetime__lte=current_time + timezone.timedelta(minutes=6),  # Less than 6 minutes away
        ).select_related('appointment', 'appointment__clinic', 'appointment__parent', 'created_by')
        
        logger.info(f"Found {meetings_needing_reminders.count()} meetings needing reminder emails")
        
        if meetings_needing_reminders.exists():
            for meeting in meetings_needing_reminders:
                try:
                    time_until_meeting = meeting.scheduled_datetime - current_time
                    minutes_until_meeting = time_until_meeting.total_seconds() / 60
                    
                    logger.info(f"Processing meeting {meeting.id} - {meeting.appointment.name}")
                    logger.info(f"Meeting scheduled for: {meeting.scheduled_datetime}")
                    logger.info(f"Minutes until meeting: {minutes_until_meeting:.1f}")
                    
                    # Only send reminder if meeting is approximately 5 minutes away (4-6 minute window)
                    if 4 <= minutes_until_meeting <= 6:
                        logger.info(f"Sending reminder emails for meeting {meeting.id}")
                        
                        # Send reminder emails
                        email_sent = EmailService.send_meeting_reminder_emails(meeting)
                        
                        if email_sent:
                            logger.info(f"✅ Reminder emails sent successfully for meeting {meeting.id}")
                        else:
                            logger.error(f"❌ Failed to send reminder emails for meeting {meeting.id}")
                    else:
                        logger.info(f"⏰ Meeting {meeting.id} not in 5-minute reminder window yet")
                        
                except Exception as meeting_error:
                    logger.error(f"❌ Error processing meeting {meeting.id}: {str(meeting_error)}")
                    continue
        else:
            logger.info("No meetings found needing reminder emails at this time")
        
        logger.info("=== MEETING REMINDER CRON JOB COMPLETED ===")
        return f"Processed {meetings_needing_reminders.count()} meetings for reminders"
        
    except Exception as e:
        logger.error(f"❌ Error in meeting reminder cron job: {str(e)}")
        raise self.retry(exc=e, countdown=60, max_retries=3)


@shared_task(bind=True)
def cleanup_old_meetings_task(self):
    """
    Optional task to cleanup old completed meetings
    Runs daily to mark old meetings as completed
    """
    try:
        logger.info("=== CLEANUP OLD MEETINGS TASK STARTED ===")
        current_time = timezone.now()
        
        # Find meetings that are past their scheduled time + duration but still marked as scheduled
        old_meetings = Meeting.objects.filter(
            status='scheduled',
            scheduled_datetime__lt=current_time - timezone.timedelta(hours=1)  # 1 hour past scheduled time
        )
        
        updated_count = 0
        for meeting in old_meetings:
            meeting.status = 'completed'
            meeting.save()
            updated_count += 1
            logger.info(f"Marked meeting {meeting.id} as completed")
        
        logger.info(f"=== CLEANUP COMPLETED: {updated_count} meetings updated ===")
        return f"Updated {updated_count} old meetings to completed status"
        
    except Exception as e:
        logger.error(f"❌ Error in cleanup old meetings task: {str(e)}")
        raise self.retry(exc=e, countdown=300, max_retries=2)
    
@shared_task(name="tasks.update_single_donor_embedding")
def update_single_donor_embedding_task(donor_id: str):
    """
    Celery task to create or update the embedding for a single donor.
    Triggered on donor creation or significant update.
    """
    try:
        donor = Donor.objects.get(id=donor_id)
        embedding_service = EmbeddingService()

        # 1. Prepare data and metadata
        donor_data = prepare_donor_data_for_embedding(donor)
        pinecone_metadata = prepare_metadata_for_pinecone(donor)
        
        # 2. Generate descriptive text and embedding
        donor_text = embedding_service.create_donor_text(donor_data)
        embedding = embedding_service.generate_embedding(donor_text)
        
        # 3. Store in Pinecone
        embedding_service.store_donor_embedding(
            donor_id=donor.donor_id,
            clinic_id=str(donor.clinic.id), # Ensure clinic_id is a string
            embedding=embedding,
            metadata=pinecone_metadata
        )
        logger.info(f"Successfully updated embedding for Donor ID: {donor.donor_id}")
        return f"Embedding updated for {donor.donor_id}"
    except Donor.DoesNotExist:
        logger.error(f"Donor with id {donor_id} not found for embedding task.")
    except Exception as e:
        logger.error(f"Error in update_single_donor_embedding_task for donor {donor_id}: {e}", exc_info=True)
        # The task can be retried automatically by Celery configuration
        raise


@shared_task(name="tasks.bulk_create_donors_and_embeddings")
def bulk_create_donors_and_embeddings_task(processed_donor_list, clinic_id):
    try:
        # --- FIX STARTS HERE ---
        
        # 1. Fetch the clinic user instance once using the provided ID.
        try:
            clinic_user = User.objects.get(id=clinic_id)
        except User.DoesNotExist:
            logger.error(f"Cannot perform bulk import: Clinic with ID {clinic_id} does not exist.")
            return f"Import failed: Clinic {clinic_id} not found."

        # 2. Re-assign the clinic and created_by references to each donor's data.
        #    This is necessary because model objects can't be passed directly to Celery tasks.
        donors_to_create = []
        for data in processed_donor_list:
            data['clinic'] = clinic_user
            data['created_by'] = clinic_user # Also assign the creator
            donors_to_create.append(Donor(**data))
            
        # --- FIX ENDS HERE ---
        
        # Bulk create donors in a single DB query
        created_donors = Donor.objects.bulk_create(donors_to_create)
        
        logger.info(f"Successfully bulk-created {len(created_donors)} donors for clinic {clinic_id}.")
        
        # Prepare data for embedding
        embedding_data_list = []
        for donor in created_donors:
            donor_data = prepare_donor_data_for_embedding(donor)
            # Ensure clinic_id is a string for the embedding service metadata
            donor_data['clinic_id'] = str(donor.clinic_id)
            embedding_data_list.append(donor_data)
        
        # Bulk process and store embeddings in Pinecone
        if embedding_data_list:
            embedding_service = EmbeddingService()
            embedding_service.bulk_process_and_store_embeddings(embedding_data_list)
            
        logger.info(f"Successfully queued bulk embedding for {len(embedding_data_list)} donors.")
        return f"Import and embedding complete for {len(created_donors)} donors."

    except Exception as e:
        # The original traceback is useful, so we log it
        logger.error(f"Critical error in bulk_create_donors_and_embeddings_task for clinic {clinic_id}: {e}", exc_info=True)
        # Re-raising the exception will cause the task to be marked as 'FAILED' in Celery, which is correct.
        raise