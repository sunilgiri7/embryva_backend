import stripe
from django.conf import settings
from apis.models import User, SubscriptionPlan

stripe.api_key = settings.STRIPE_SECRET_KEY

def create_stripe_customer(user: User):
    """Creates a Stripe Customer object for a given user and saves the ID."""
    if not user.stripe_customer_id:
        customer = stripe.Customer.create(
            email=user.email,
            name=user.get_full_name(),
            metadata={'user_id': user.id}
        )
        user.stripe_customer_id = customer.id
        user.save()
    return user.stripe_customer_id

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