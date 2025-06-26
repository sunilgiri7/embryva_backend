from django.core.mail import send_mail
from django.template.loader import render_to_string
from django.utils.html import strip_tags
from django.conf import settings
from django.utils import timezone
from .models import Meeting, MeetingParticipant, User
import logging
import uuid

logger = logging.getLogger(__name__)

class EmailService:
    """Service class for handling meeting-related email notifications"""
    
    @staticmethod
    def send_meeting_creation_emails(meeting):
        """Send meeting creation emails to all participants"""
        try:
            # Create participants for the meeting
            EmailService.create_meeting_participants(meeting)
            
            # Send emails to all participants
            participants = meeting.participants.all()
            
            for participant in participants:
                success = EmailService.send_meeting_creation_email(participant)
                if success:
                    participant.creation_email_sent = True
                    participant.creation_email_sent_at = timezone.now()
                    participant.save()
            
            # Update meeting email status
            meeting.creation_email_sent = True
            meeting.save()
            
            logger.info(f"Meeting creation emails sent for meeting {meeting.id}")
            return True
            
        except Exception as e:
            logger.error(f"Error sending meeting creation emails: {str(e)}")
            return False
    
    @staticmethod
    def create_meeting_participants(meeting):
        """Create meeting participants based on appointment details"""
        appointment = meeting.appointment
        participants_to_create = []
        
        # Add admin/subadmin who created the meeting
        participants_to_create.append({
            'user': meeting.created_by,
            'type': 'admin' if meeting.created_by.is_admin else 'subadmin'
        })
        
        # Add clinic
        participants_to_create.append({
            'user': appointment.clinic,
            'type': 'clinic'
        })
        
        # Add parent if exists
        if appointment.parent:
            participants_to_create.append({
                'user': appointment.parent,
                'type': 'parent'
            })
        
        # Create participant records
        for participant_data in participants_to_create:
            MeetingParticipant.objects.get_or_create(
                meeting=meeting,
                user=participant_data['user'],
                defaults={'participant_type': participant_data['type']}
            )
    
    @staticmethod
    def send_meeting_creation_email(participant):
        """Send meeting creation email to a specific participant"""
        try:
            meeting = participant.meeting
            appointment = meeting.appointment
            
            subject = f"Meeting Scheduled - {appointment.name}"
            
            context = {
                'participant_name': participant.user.get_full_name(),
                'appointment_name': appointment.name,
                'appointment_reason': appointment.get_reason_for_consultation_display(),
                'clinic_name': appointment.clinic.get_full_name(),
                'meeting_datetime': meeting.scheduled_datetime.strftime('%B %d, %Y at %I:%M %p'),
                'meeting_link': meeting.meeting_link,
                'meeting_id': meeting.meeting_id or 'N/A',
                'passcode': meeting.passcode or 'N/A',
                'duration': meeting.duration_minutes,
                'meeting_type': meeting.get_meeting_type_display(),
            }
            
            # Try multiple template paths
            template_paths = [
                'templates/emails/meeting_creation.html',
                'apis/emails/meeting_creation.html',
            ]
            
            html_message = None
            for template_path in template_paths:
                try:
                    html_message = render_to_string(template_path, context)
                    break
                except Exception as template_error:
                    logger.warning(f"Template {template_path} not found: {template_error}")
                    continue
            
            if not html_message:
                # Fallback to plain text if no template found
                html_message = f"""
                <html>
                <body>
                    <h2>Meeting Scheduled</h2>
                    <p>Hello {context['participant_name']},</p>
                    <p>A meeting has been scheduled for appointment: <strong>{context['appointment_name']}</strong></p>
                    <p><strong>Meeting Details:</strong></p>
                    <ul>
                        <li><strong>Reason:</strong> {context['appointment_reason']}</li>
                        <li><strong>Clinic:</strong> {context['clinic_name']}</li>
                        <li><strong>Date & Time:</strong> {context['meeting_datetime']}</li>
                        <li><strong>Duration:</strong> {context['duration']} minutes</li>
                        <li><strong>Meeting Type:</strong> {context['meeting_type']}</li>
                    </ul>
                    <p><strong>Meeting Access:</strong></p>
                    <ul>
                        <li><strong>Meeting Link:</strong> <a href="{context['meeting_link']}">{context['meeting_link']}</a></li>
                        <li><strong>Meeting ID:</strong> {context['meeting_id']}</li>
                        <li><strong>Passcode:</strong> {context['passcode']}</li>
                    </ul>
                    <p>You will receive a reminder email 5 minutes before the meeting starts.</p>
                    <p>Thank you!</p>
                </body>
                </html>
                """
                logger.info("Using fallback HTML template for meeting creation email")
            
            plain_message = strip_tags(html_message)
            
            send_mail(
                subject=subject,
                message=plain_message,
                from_email=settings.DEFAULT_FROM_EMAIL,
                recipient_list=[participant.user.email],
                html_message=html_message,
                fail_silently=False,
            )
            
            logger.info(f"Meeting creation email sent to {participant.user.email}")
            return True
            
        except Exception as e:
            logger.error(f"Error sending meeting creation email to {participant.user.email}: {str(e)}")
            return False
    
    @staticmethod
    def send_meeting_reminder_emails(meeting):
        """Send reminder emails 5 minutes before meeting with enhanced logging"""
        try:
            logger.info(f"🔄 Starting reminder email process for meeting {meeting.id}")
            logger.info(f"📅 Meeting details: {meeting.appointment.name} at {meeting.scheduled_datetime}")
            
            participants = meeting.participants.filter(reminder_email_sent=False)
            logger.info(f"👥 Found {participants.count()} participants who haven't received reminder emails")
            
            email_success_count = 0
            email_failure_count = 0
            
            for participant in participants:
                logger.info(f"📧 Sending reminder email to {participant.user.email} ({participant.participant_type})")
                
                success = EmailService.send_meeting_reminder_email(participant)
                if success:
                    participant.reminder_email_sent = True
                    participant.reminder_email_sent_at = timezone.now()
                    participant.save()
                    email_success_count += 1
                    logger.info(f"✅ Reminder email sent successfully to {participant.user.email}")
                else:
                    email_failure_count += 1
                    logger.error(f"❌ Failed to send reminder email to {participant.user.email}")
            
            # Update meeting reminder status only if all emails were sent successfully
            if email_failure_count == 0 and email_success_count > 0:
                meeting.reminder_email_sent = True
                meeting.save()
                logger.info(f"✅ Meeting reminder status updated - all emails sent successfully")
            elif email_failure_count > 0:
                logger.warning(f"⚠️ Meeting reminder status NOT updated - {email_failure_count} emails failed")
            
            logger.info(f"📊 Reminder email summary for meeting {meeting.id}:")
            logger.info(f"   ✅ Successful: {email_success_count}")
            logger.info(f"   ❌ Failed: {email_failure_count}")
            logger.info(f"   📧 Total participants: {participants.count()}")
            
            return email_failure_count == 0  # Return True only if no failures
            
        except Exception as e:
            logger.error(f"❌ Critical error in send_meeting_reminder_emails: {str(e)}")
            return False
    
    @staticmethod
    def send_meeting_reminder_email(participant):
        """Send meeting reminder email to a specific participant with enhanced logging"""
        try:
            meeting = participant.meeting
            appointment = meeting.appointment
            
            subject = f"🔔 Meeting Reminder - Starting in 5 minutes"
            
            context = {
                'participant_name': participant.user.get_full_name(),
                'appointment_name': appointment.name,
                'clinic_name': appointment.clinic.get_full_name(),
                'meeting_datetime': meeting.scheduled_datetime.strftime('%Y-%m-%d %H:%M'),
                'meeting_link': meeting.meeting_link,
                'meeting_id': meeting.meeting_id or 'N/A',
                'passcode': meeting.passcode or 'N/A',
                'participant_type': participant.get_participant_type_display(),
            }
            
            # Enhanced template paths
            template_paths = [
                'templates/emails/meeting_reminder.html',
                'apis/emails/meeting_reminder.html',
                'emails/meeting_reminder.html'
            ]
            
            html_message = None
            for template_path in template_paths:
                try:
                    html_message = render_to_string(template_path, context)
                    logger.info(f"📄 Using email template: {template_path}")
                    break
                except Exception as template_error:
                    logger.debug(f"Template {template_path} not found: {template_error}")
                    continue
            
            if not html_message:
                # Enhanced fallback HTML template
                html_message = f"""
                <!DOCTYPE html>
                <html>
                <head>
                    <meta charset="utf-8">
                    <title>Meeting Reminder</title>
                    <style>
                        body {{ font-family: Arial, sans-serif; line-height: 1.6; color: #333; }}
                        .container {{ max-width: 600px; margin: 0 auto; padding: 20px; }}
                        .header {{ background: #007bff; color: white; padding: 20px; text-align: center; }}
                        .content {{ padding: 20px; background: #f9f9f9; }}
                        .details {{ background: white; padding: 15px; margin: 15px 0; border-left: 4px solid #007bff; }}
                        .join-button {{ display: inline-block; background: #28a745; color: white !important; padding: 12px 25px; text-decoration: none; border-radius: 5px; margin: 20px 0; }}
                        .urgent {{ color: #dc3545; font-weight: bold; }}
                    </style>
                </head>
                <body>
                    <div class="container">
                        <div class="header">
                            <h1>🔔 Meeting Reminder</h1>
                            <p class="urgent">Starting in 5 minutes!</p>
                        </div>
                        <div class="content">
                            <p>Hello <strong>{context['participant_name']}</strong>,</p>
                            <p class="urgent">Your meeting is starting in 5 minutes!</p>
                            
                            <div class="details">
                                <h3>📋 Meeting Details:</h3>
                                <ul>
                                    <li><strong>Patient:</strong> {context['appointment_name']}</li>
                                    <li><strong>Clinic:</strong> {context['clinic_name']}</li>
                                    <li><strong>Date & Time:</strong> {context['meeting_datetime']}</li>
                                    <li><strong>Your Role:</strong> {context['participant_type']}</li>
                                </ul>
                            </div>
                            
                            <div class="details">
                                <h3>🔗 Meeting Access:</h3>
                                <ul>
                                    <li><strong>Meeting Link:</strong> <a href="{context['meeting_link']}">{context['meeting_link']}</a></li>
                                    <li><strong>Meeting ID:</strong> {context['meeting_id']}</li>
                                    <li><strong>Passcode:</strong> {context['passcode']}</li>
                                </ul>
                            </div>
                            
                            <div style="text-align: center;">
                                <a href="{context['meeting_link']}" class="join-button">🚀 Join Meeting Now</a>
                            </div>
                            
                            <p><small>This is an automated reminder sent 5 minutes before your scheduled meeting.</small></p>
                        </div>
                    </div>
                </body>
                </html>
                """
                logger.info("📄 Using enhanced fallback HTML template for meeting reminder email")
            
            plain_message = strip_tags(html_message)
            
            logger.info(f"📤 Sending reminder email to {participant.user.email}")
            logger.info(f"📧 Subject: {subject}")
            
            send_mail(
                subject=subject,
                message=plain_message,
                from_email=settings.DEFAULT_FROM_EMAIL,
                recipient_list=[participant.user.email],
                html_message=html_message,
                fail_silently=False,
            )
            
            logger.info(f"✅ Meeting reminder email sent successfully to {participant.user.email}")
            return True
            
        except Exception as e:
            logger.error(f"❌ Error sending meeting reminder email to {participant.user.email}: {str(e)}")
            logger.error(f"❌ Error details: {type(e).__name__}: {str(e)}")
            return False