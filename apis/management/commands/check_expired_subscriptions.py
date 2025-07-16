from django.core.mail import send_mail
from django.template.loader import render_to_string
from django.conf import settings
from django.core.management.base import BaseCommand
from apis.models import UserSubscription

class Command(BaseCommand):
    help = 'Check and update expired subscriptions'

    def handle(self, *args, **options):
        expired_count = 0
        active_subscriptions = UserSubscription.objects.filter(status='active')
        
        for subscription in active_subscriptions:
            if subscription.check_expiry():
                expired_count += 1
                user_email = subscription.user.email

                # Send notification email
                subject = "Your Subscription Has Expired"
                message = render_to_string('emails/subscription_expired.html', {
                    'user': subscription.user,
                    'plan': subscription.plan,
                    'end_date': subscription.end_date
                })

                send_mail(
                    subject,
                    message,
                    settings.DEFAULT_FROM_EMAIL
                    [user_email],
                    fail_silently=False,
                )

                self.stdout.write(
                    self.style.WARNING(f'Expired subscription for {user_email} — email sent')
                )

        self.stdout.write(
            self.style.SUCCESS(f'Successfully processed {expired_count} expired subscriptions')
        )