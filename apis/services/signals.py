from django.db.models.signals import post_save
from django.dispatch import receiver
import logging
import threading

from apis.models import Donor, SubscriptionPlan
from apis.services.embeddingsMatching import EmbeddingService
from apis.services.stripe_service import sync_subscription_plan
from apis.utils import prepare_donor_data_for_embedding, prepare_metadata_for_pinecone

logger = logging.getLogger(__name__)

def generate_and_store_embedding(donor_instance):
    try:
        logger.info(f"Starting embedding generation for donor {donor_instance.donor_id}")
        embedding_service = EmbeddingService()
        
        # Prepare comprehensive donor data for embedding
        donor_data = prepare_donor_data_for_embedding(donor_instance)
        
        # Generate embedding text and vector
        donor_text = embedding_service.create_donor_text(donor_data)
        embedding = embedding_service.generate_embedding(donor_text)
        
        # Prepare metadata with null value filtering
        metadata = prepare_metadata_for_pinecone(donor_instance)
        
        # Store embedding in Pinecone
        embedding_service.store_donor_embedding(
            donor_id=donor_instance.donor_id,
            clinic_id=str(donor_instance.clinic.id),
            embedding=embedding,
            metadata=metadata
        )
        
        logger.info(f"Successfully generated and stored embedding for donor {donor_instance.donor_id}")
        
    except Exception as e:
        logger.error(f"Failed to generate embedding for donor {donor_instance.donor_id}: {e}", exc_info=True)

@receiver(post_save, sender=Donor)
def donor_post_save_receiver(sender, instance, created, **kwargs):
    try:
        thread = threading.Thread(target=generate_and_store_embedding, args=(instance,))
        thread.daemon = True
        thread.start()
    except Exception as e:
        logger.error(f"Error in donor_post_save_receiver for donor {instance.donor_id}: {e}")

@receiver(post_save, sender=SubscriptionPlan)
def handle_subscription_plan_save(sender, instance, created, **kwargs):
    if not instance.stripe_price_id:
        sync_subscription_plan(instance)