from django.db.models.signals import post_save
from django.dispatch import receiver
import logging
import threading
from django.db.models.signals import post_save, pre_delete
from apis.models import Donor, SubscriptionPlan
from apis.services.embeddingsMatching import EmbeddingService
from apis.services.stripe_service import sync_subscription_plan
from apis.tasks import update_single_donor_embedding_task
from apis.utils import prepare_donor_data_for_embedding, prepare_metadata_for_pinecone

logger = logging.getLogger(__name__)
EMBEDDING_RELEVANT_FIELDS = {
    'gender', 'donor_type', 'height', 'eye_color', 'hair_color', 'ethnicity',
    'education_level', 'occupation', 'blood_group', 'smoking_status',
    'religion', 'personality_traits', 'interests_hobbies', 'date_of_birth'
}

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
def donor_post_save_receiver(sender, instance, created, update_fields, **kwargs):
    if created:
        print(f"New donor created: {instance.donor_id}. Queuing embedding task.")
        update_single_donor_embedding_task.delay(instance.id)
    elif update_fields is not None:
        # Check if embedding-relevant fields were updated
        if any(field in update_fields for field in EMBEDDING_RELEVANT_FIELDS):
            print(f"Relevant donor fields updated for {instance.donor_id}. Queuing embedding update task.")
            update_single_donor_embedding_task.delay(instance.id)
    else:
        if hasattr(instance, 'needs_embedding_update') and instance.needs_embedding_update:
            print(f"Donor {instance.donor_id} flagged for embedding update. Queuing embedding update task.")
            update_single_donor_embedding_task.delay(instance.id)
            # Reset the flag to avoid repeated updates
            instance.needs_embedding_update = False
            instance.save(update_fields=['needs_embedding_update'])
@receiver(pre_delete, sender=Donor)
def donor_pre_delete_receiver(sender, instance, **kwargs):
    logger.info(f"Donor {instance.donor_id} is being deleted. Removing from Pinecone.")
    try:
        embedding_service = EmbeddingService()
        embedding_service.delete_donor_embedding(
            donor_id=instance.donor_id,
            clinic_id=str(instance.clinic.id)
        )
        logger.info(f"Successfully deleted vector for donor {instance.donor_id} from Pinecone.")
    except Exception as e:
        logger.error(
            f"Failed to delete vector for donor {instance.donor_id} from Pinecone. "
            f"It will need to be cleaned up manually. Error: {e}",
            exc_info=True
        )

@receiver(post_save, sender=SubscriptionPlan)
def handle_subscription_plan_save(sender, instance, created, **kwargs):
    if not instance.stripe_price_id:
        sync_subscription_plan(instance)