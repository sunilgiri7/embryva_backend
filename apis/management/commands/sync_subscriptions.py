from django.core.management.base import BaseCommand
from django.utils import timezone
from datetime import datetime
import stripe
from django.conf import settings
from apis.models import UserSubscription  # Replace with your app name

stripe.api_key = settings.STRIPE_SECRET_KEY

class Command(BaseCommand):
    help = 'Sync subscription statuses with Stripe'

    def add_arguments(self, parser):
        parser.add_argument(
            '--fix-inconsistencies',
            action='store_true',
            help='Fix inconsistencies between local and Stripe data',
        )

    def handle(self, *args, **options):
        fix_inconsistencies = options['fix_inconsistencies']
        
        self.stdout.write('Starting subscription sync...')
        
        # Get all subscriptions with Stripe IDs
        subscriptions = UserSubscription.objects.filter(
            stripe_subscription_id__isnull=False
        )
        
        updated_count = 0
        error_count = 0
        
        for subscription in subscriptions:
            try:
                # Get subscription from Stripe
                stripe_sub = stripe.Subscription.retrieve(subscription.stripe_subscription_id)
                
                # Convert timestamps
                stripe_start = timezone.make_aware(datetime.fromtimestamp(stripe_sub.current_period_start))
                stripe_end = timezone.make_aware(datetime.fromtimestamp(stripe_sub.current_period_end))
                
                # Check for inconsistencies
                needs_update = False
                changes = []
                
                # Check status
                stripe_status_map = {
                    'active': 'active',
                    'canceled': 'cancelled',
                    'past_due': 'active',  # Keep as active but flag payment issue
                    'unpaid': 'inactive',
                    'incomplete': 'inactive',
                    'incomplete_expired': 'expired',
                    'trialing': 'active',
                }
                
                expected_status = stripe_status_map.get(stripe_sub.status, 'inactive')
                if subscription.status != expected_status:
                    changes.append(f"Status: {subscription.status} -> {expected_status}")
                    if fix_inconsistencies:
                        subscription.status = expected_status
                        needs_update = True
                
                # Check dates
                if abs((subscription.start_date - stripe_start).total_seconds()) > 3600:  # 1 hour tolerance
                    changes.append(f"Start date: {subscription.start_date} -> {stripe_start}")
                    if fix_inconsistencies:
                        subscription.start_date = stripe_start
                        needs_update = True
                
                if abs((subscription.end_date - stripe_end).total_seconds()) > 3600:  # 1 hour tolerance
                    changes.append(f"End date: {subscription.end_date} -> {stripe_end}")
                    if fix_inconsistencies:
                        subscription.end_date = stripe_end
                        needs_update = True
                
                if changes:
                    self.stdout.write(
                        self.style.WARNING(
                            f'Inconsistency found for {subscription.user.email}: {", ".join(changes)}'
                        )
                    )
                    
                    if needs_update:
                        subscription.save()
                        updated_count += 1
                        self.stdout.write(
                            self.style.SUCCESS(f'Updated subscription for {subscription.user.email}')
                        )
                
            except stripe.error.StripeError as e:
                error_count += 1
                self.stdout.write(
                    self.style.ERROR(
                        f'Stripe error for subscription {subscription.id}: {e}'
                    )
                )
                
                # If subscription doesn't exist in Stripe, mark as cancelled
                if 'No such subscription' in str(e) and fix_inconsistencies:
                    subscription.status = 'cancelled'
                    subscription.save()
                    self.stdout.write(
                        self.style.WARNING(
                            f'Marked subscription as cancelled for {subscription.user.email} (not found in Stripe)'
                        )
                    )
                    
            except Exception as e:
                error_count += 1
                self.stdout.write(
                    self.style.ERROR(f'Error processing subscription {subscription.id}: {e}')
                )
        
        self.stdout.write(
            self.style.SUCCESS(
                f'Sync completed. Updated: {updated_count}, Errors: {error_count}'
            )
        )