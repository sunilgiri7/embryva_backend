import stripe
from django.conf import settings
from apis.models import User, SubscriptionPlan

stripe.api_key = settings.STRIPE_SECRET_KEY

def create_stripe_customer(user):
    """Create or retrieve Stripe customer for user"""
    if user.stripe_customer_id:
        return user.stripe_customer_id
    
    try:
        # Create new customer in Stripe
        customer = stripe.Customer.create(
            email=user.email,
            name=user.get_full_name(),
            phone=user.phone_number,
            metadata={
                'user_id': str(user.id),
                'user_type': user.user_type
            }
        )
        
        # Save customer ID to user
        user.stripe_customer_id = customer.id
        user.save(update_fields=['stripe_customer_id'])
        
        return customer.id
    except Exception as e:
        print(f"Error creating Stripe customer: {e}")
        raise

def sync_subscription_plan(plan: SubscriptionPlan):
    try:
        # Create or retrieve the Stripe Product
        product = stripe.Product.create(
            name=plan.name,
            description=plan.features,
            metadata={'plan_id': plan.id}
        )

        # Create the Stripe Price
        price = stripe.Price.create(
            product=product.id,
            unit_amount=int(plan.price * 100), 
            currency='inr',
            recurring={'interval': plan.billing_cycle}, 
        )

        # Save the Stripe Price ID to our plan model
        plan.stripe_price_id = price.id
        plan.save()

        return price.id
    except Exception as e:
        # Handle potential errors, e.g., logging
        print(f"Error syncing plan {plan.id} with Stripe: {e}")
        return None