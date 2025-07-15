from django.db.models.signals import post_save
from django.dispatch import receiver
import logging
import threading

from apis.models import Donor, SubscriptionPlan
from apis.services.embeddingsMatching import EmbeddingService
from apis.services.stripe_service import sync_subscription_plan

logger = logging.getLogger(__name__)

def generate_and_store_embedding(donor_instance):
    try:
        logger.info(f"Signal triggered: Starting embedding generation for donor {donor_instance.donor_id}")
        embedding_service = EmbeddingService()
        
        donor_data = {
            'gender': donor_instance.gender, 'donor_type': donor_instance.donor_type,
            'height': donor_instance.height, 'eye_color': donor_instance.eye_color,
            'hair_color': donor_instance.hair_color, 'ethnicity': donor_instance.ethnicity,
            'education_level': donor_instance.education_level, 'occupation': donor_instance.occupation,
            'blood_group': donor_instance.blood_group, 'smoking_status': donor_instance.smoking_status,
            'religion': donor_instance.religion, 'date_of_birth': donor_instance.date_of_birth,
            'personality_traits': donor_instance.personality_traits,
            'interests_hobbies': donor_instance.interests_hobbies,
            'genetic_conditions': donor_instance.genetic_conditions,
        }

        donor_text = embedding_service.create_donor_text(donor_data)
        embedding = embedding_service.generate_embedding(donor_text)
        
        metadata = {
            'donor_type': donor_instance.donor_type, 'gender': donor_instance.gender,
            'education_level': donor_instance.education_level, 'ethnicity': donor_instance.ethnicity,
            'location': donor_instance.location,
        }
        
        embedding_service.store_donor_embedding(
            donor_id=donor_instance.donor_id,
            clinic_id=str(donor_instance.clinic.id),
            embedding=embedding,
            metadata=metadata
        )
        logger.info(f"Successfully generated and stored embedding for donor {donor_instance.donor_id}")
        
    except Exception as e:
        logger.error(f"Failed to generate embedding for donor {donor_instance.donor_id} via signal: {e}", exc_info=True)

@receiver(post_save, sender=Donor)
def donor_post_save_receiver(sender, instance, created, **kwargs):
    thread = threading.Thread(target=generate_and_store_embedding, args=(instance,))
    thread.daemon = True
    thread.start()

@receiver(post_save, sender=SubscriptionPlan)
def handle_subscription_plan_save(sender, instance, created, **kwargs):
    if not instance.stripe_price_id:
        sync_subscription_plan(instance)