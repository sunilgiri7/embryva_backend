# tasks.py
from apis.email_service import EmailService
from celery import shared_task
from django.utils import timezone
from django.conf import settings
from .models import Meeting
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