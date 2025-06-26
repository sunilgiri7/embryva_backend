# management/commands/create_default_subscription_plans.py
from django.core.management.base import BaseCommand
from django.db import transaction
from apis.models import SubscriptionPlan  # Replace 'apis' with your actual app name

class Command(BaseCommand):
    help = 'Create 3 default subscription plans: monthly, quarterly, and yearly'

    def handle(self, *args, **options):
        """Create 3 default subscription plans if they don't exist"""
        
        default_plans = [
            # Monthly Plan
            {
                'name': 'standard',
                'billing_cycle': 'monthly',
                'price': 19.99,
                'description': 'Monthly subscription plan with full access to all features',
                'features': {
                    'max_children': 'unlimited',
                    'basic_tracking': True,
                    'advanced_analytics': True,
                    'email_support': True,
                    'mobile_app': True,
                    'data_export': True,
                    'premium_support': True,
                    'family_sharing': True,
                    'api_access': True,
                    'custom_reports': True,
                    'priority_support': True
                }
            },
            
            # Quarterly Plan
            {
                'name': 'standard',
                'billing_cycle': 'quarterly',
                'price': 53.99,
                'description': 'Quarterly subscription plan with full access to all features (10% discount)',
                'features': {
                    'max_children': 'unlimited',
                    'basic_tracking': True,
                    'advanced_analytics': True,
                    'email_support': True,
                    'mobile_app': True,
                    'data_export': True,
                    'premium_support': True,
                    'family_sharing': True,
                    'api_access': True,
                    'custom_reports': True,
                    'priority_support': True
                }
            },
            
            # Yearly Plan
            {
                'name': 'standard',
                'billing_cycle': 'yearly',
                'price': 199.99,
                'description': 'Yearly subscription plan with full access to all features (17% discount)',
                'features': {
                    'max_children': 'unlimited',
                    'basic_tracking': True,
                    'advanced_analytics': True,
                    'email_support': True,
                    'mobile_app': True,
                    'data_export': True,
                    'premium_support': True,
                    'family_sharing': True,
                    'api_access': True,
                    'custom_reports': True,
                    'priority_support': True
                }
            }
        ]

        created_count = 0
        updated_count = 0
        skipped_count = 0

        with transaction.atomic():
            for plan_data in default_plans:
                plan, created = SubscriptionPlan.objects.get_or_create(
                    name=plan_data['name'],
                    billing_cycle=plan_data['billing_cycle'],
                    defaults={
                        'price': plan_data['price'],
                        'description': plan_data['description'],
                        'features': plan_data['features'],
                        'is_active': True
                    }
                )
                
                if created:
                    created_count += 1
                    self.stdout.write(
                        self.style.SUCCESS(
                            f'✓ Created plan: {plan.get_name_display()} - {plan.get_billing_cycle_display()} (${plan.price})'
                        )
                    )
                else:
                    # Update existing plan if needed
                    updated = False
                    if plan.price != plan_data['price']:
                        plan.price = plan_data['price']
                        updated = True
                    if plan.description != plan_data['description']:
                        plan.description = plan_data['description']
                        updated = True
                    if plan.features != plan_data['features']:
                        plan.features = plan_data['features']
                        updated = True
                    
                    if updated:
                        plan.save()
                        updated_count += 1
                        self.stdout.write(
                            self.style.WARNING(
                                f'⚠ Updated plan: {plan.get_name_display()} - {plan.get_billing_cycle_display()} (${plan.price})'
                            )
                        )
                    else:
                        skipped_count += 1
                        self.stdout.write(
                            f'→ Plan already exists: {plan.get_name_display()} - {plan.get_billing_cycle_display()} (${plan.price})'
                        )

        # Display summary
        self.stdout.write('\n' + '='*60)
        self.stdout.write(
            self.style.SUCCESS(
                f'SUMMARY: {created_count} plans created, {updated_count} plans updated, {skipped_count} plans skipped'
            )
        )
        
        # Display plan breakdown by billing cycle
        self.stdout.write('\nPlan breakdown by billing cycle:')
        for cycle in ['monthly', 'quarterly', 'yearly']:
            count = SubscriptionPlan.objects.filter(billing_cycle=cycle).count()
            self.stdout.write(f'  {cycle.title()}: {count} plans')
        
        self.stdout.write('='*60)