import json
import asyncio
from apis.models import Donor, FertilityProfile
from apis.services.embeddingsMatching import DonorMatchingEngine, EmbeddingService
from channels.generic.websocket import AsyncWebsocketConsumer
from channels.db import database_sync_to_async
from django.contrib.auth import get_user_model
from asgiref.sync import sync_to_async
import logging

logger = logging.getLogger(__name__)
User = get_user_model()

class RealtimeMatchingConsumer(AsyncWebsocketConsumer):
    """WebSocket consumer for real-time donor matching updates"""
    
    async def connect(self):
        # Get user from scope (set by auth middleware)
        self.user = self.scope.get('user')
        
        if not self.user or not self.user.is_authenticated:
            await self.close(code=4001)  # Unauthorized
            return
            
        if not self.user.is_parent:
            await self.close(code=4003)  # Forbidden - only parents can use this
            return
            
        # Create a unique group name for this user
        self.group_name = f"matching_{self.user.id}"
        
        # Join the group
        await self.channel_layer.group_add(self.group_name, self.channel_name)
        
        # Accept the connection
        await self.accept()
        
        # Send initial connection confirmation
        await self.send(text_data=json.dumps({
            'type': 'connection_established',
            'message': 'Connected to real-time matching service'
        }))
        
        logger.info(f"User {self.user.id} connected to real-time matching")

    async def disconnect(self, close_code):
        """Handle WebSocket disconnection"""
        if hasattr(self, 'group_name'):
            await self.channel_layer.group_discard(self.group_name, self.channel_name)
        
        logger.info(f"User {getattr(self, 'user', {}).get('id', 'unknown')} disconnected from real-time matching")

    async def receive(self, text_data):
        """Handle incoming WebSocket messages"""
        try:
            data = json.loads(text_data)
            message_type = data.get('type')
            
            if message_type == 'update_preferences':
                await self.handle_preference_update(data)
            elif message_type == 'get_initial_matches':
                await self.handle_initial_matches(data)
            else:
                await self.send_error("Unknown message type")
                
        except json.JSONDecodeError:
            await self.send_error("Invalid JSON format")
        except Exception as e:
            logger.error(f"Error processing WebSocket message: {e}", exc_info=True)
            await self.send_error("Internal server error")

    async def handle_preference_update(self, data):
        """Handle preference updates and calculate real-time matches"""
        try:
            preferences = data.get('preferences', {})
            
            # Validate required fields
            if not preferences.get('donor_type_preference'):
                await self.send_error("donor_type_preference is required")
                return
            
            # Get or create temporary profile data
            profile_data = await self.build_profile_data(preferences)
            
            # Calculate matches in background
            await self.calculate_and_send_matches(profile_data)
            
        except Exception as e:
            logger.error(f"Error handling preference update: {e}", exc_info=True)
            await self.send_error("Failed to process preference update")

    async def handle_initial_matches(self, data):
        """Handle request for initial matches based on existing profile"""
        try:
            profile_id = data.get('profile_id')
            
            if profile_id:
                # Get existing profile
                profile = await self.get_fertility_profile(profile_id)
                if profile:
                    profile_data = await self.convert_profile_to_dict(profile)
                    await self.calculate_and_send_matches(profile_data)
                else:
                    await self.send_error("Profile not found")
            else:
                await self.send_error("profile_id is required")
                
        except Exception as e:
            logger.error(f"Error handling initial matches: {e}", exc_info=True)
            await self.send_error("Failed to get initial matches")

    async def calculate_and_send_matches(self, profile_data):
        """Calculate matches and send real-time updates"""
        try:
            # Send processing started message
            await self.send(text_data=json.dumps({
                'type': 'matching_started',
                'message': 'Calculating matches...'
            }))
            
            # Run matching in thread pool to avoid blocking
            matches = await sync_to_async(self.run_matching_sync)(profile_data)
            
            # Send results
            await self.send(text_data=json.dumps({
                'type': 'matching_results',
                'data': {
                    'total_matches': len(matches),
                    'matches': matches[:10],  # Send top 10 matches
                    'summary': self.generate_match_summary(matches),
                    'timestamp': asyncio.get_event_loop().time()
                }
            }))
            
        except Exception as e:
            logger.error(f"Error calculating matches: {e}", exc_info=True)
            await self.send_error("Failed to calculate matches")

    def run_matching_sync(self, profile_data):
        """Run matching synchronously in thread pool"""
        try:
            # Create temporary profile object
            temp_profile = type('TempProfile', (), profile_data)()
            
            # Initialize services
            embedding_service = EmbeddingService()
            matching_engine = DonorMatchingEngine()
            
            # Create profile text and embedding
            profile_text = embedding_service.create_profile_text(profile_data)
            profile_embedding = embedding_service.generate_embedding(profile_text)
            
            # Get initial candidates
            similar_donors = embedding_service.search_similar_donors(
                profile_embedding=profile_embedding,
                top_k=50,  # Smaller set for real-time
                donor_type_filter=profile_data.get('donor_type_preference')
            )
            
            if not similar_donors:
                return []
            
            # Score and format results
            matches = []
            donor_ids = [d['donor_id'] for d in similar_donors]
            donors_from_db = Donor.objects.filter(
                donor_id__in=donor_ids, 
                is_active=True
            ).select_related('clinic')
            
            donor_map = {d.donor_id: d for d in donors_from_db}
            
            for similar_donor in similar_donors:
                donor = donor_map.get(similar_donor['donor_id'])
                if not donor:
                    continue
                    
                # Prepare donor data
                donor_data = {
                    'gender': donor.gender,
                    'donor_type': donor.donor_type,
                    'height': donor.height,
                    'eye_color': donor.eye_color,
                    'hair_color': donor.hair_color,
                    'ethnicity': donor.ethnicity,
                    'education_level': donor.education_level,
                    'occupation': donor.occupation,
                    'blood_group': donor.blood_group,
                    'smoking_status': donor.smoking_status,
                    'religion': donor.religion,
                    'date_of_birth': donor.date_of_birth,
                    'genetic_conditions': donor.genetic_conditions,
                    'personality_traits': donor.personality_traits,
                    'interests_hobbies': donor.interests_hobbies,
                }
                
                # Calculate scores
                detailed_score, matched_attrs, compat_scores = matching_engine.calculate_detailed_match_score(
                    donor_data, profile_data
                )
                
                # Combine scores
                final_score = (detailed_score * 0.6) + (similar_donor['similarity_score'] * 0.4)
                
                # Only include matches above threshold
                if final_score >= 0.3:  # Lower threshold for real-time
                    matches.append({
                        'donor_id': donor.donor_id,
                        'clinic_id': str(donor.clinic.id),
                        'match_percentage': round(final_score * 100, 1),
                        'matched_attributes': list(matched_attrs.keys()),
                        'compatibility_breakdown': {
                            'physical': round(compat_scores.get('physical', 0), 1),
                            'educational': round(compat_scores.get('educational', 0), 1),
                            'demographic': round(compat_scores.get('demographic', 0), 1),
                            'medical': round(compat_scores.get('medical', 0), 1),
                        }
                    })
            
            # Sort by score
            matches.sort(key=lambda x: x['match_percentage'], reverse=True)
            return matches
            
        except Exception as e:
            logger.error(f"Error in sync matching: {e}", exc_info=True)
            return []

    def generate_match_summary(self, matches):
        """Generate summary statistics for matches"""
        if not matches:
            return {
                'total': 0,
                'high_quality': 0,
                'average_score': 0,
                'best_match_score': 0
            }
        
        total = len(matches)
        high_quality = len([m for m in matches if m['match_percentage'] >= 60])
        average_score = sum(m['match_percentage'] for m in matches) / total
        best_match_score = max(m['match_percentage'] for m in matches)
        
        return {
            'total': total,
            'high_quality': high_quality,
            'average_score': round(average_score, 1),
            'best_match_score': round(best_match_score, 1)
        }

    async def build_profile_data(self, preferences):
        """Build profile data from preferences"""
        return {
            'donor_type_preference': preferences.get('donor_type_preference'),
            'location': preferences.get('location', ''),
            'preferred_height_min': preferences.get('preferred_height_min'),
            'preferred_height_max': preferences.get('preferred_height_max'),
            'preferred_ethnicity': preferences.get('preferred_ethnicity', ''),
            'preferred_eye_color': preferences.get('preferred_eye_color', ''),
            'preferred_hair_color': preferences.get('preferred_hair_color', ''),
            'preferred_education_level': preferences.get('preferred_education_level', ''),
            'genetic_screening_required': preferences.get('genetic_screening_required', True),
            'preferred_age_min': preferences.get('preferred_age_min'),
            'preferred_age_max': preferences.get('preferred_age_max'),
            'preferred_occupation': preferences.get('preferred_occupation', ''),
            'preferred_religion': preferences.get('preferred_religion', ''),
            'importance_physical': preferences.get('importance_physical', 5),
            'importance_education': preferences.get('importance_education', 5),
            'importance_medical': preferences.get('importance_medical', 8),
            'importance_personality': preferences.get('importance_personality', 5),
            'special_requirements': preferences.get('special_requirements', ''),
        }

    @database_sync_to_async
    def get_fertility_profile(self, profile_id):
        """Get fertility profile from database"""
        try:
            return FertilityProfile.objects.get(id=profile_id, parent=self.user)
        except FertilityProfile.DoesNotExist:
            return None

    @database_sync_to_async
    def convert_profile_to_dict(self, profile):
        """Convert profile model to dictionary"""
        return {
            'donor_type_preference': profile.donor_type_preference,
            'location': profile.location,
            'preferred_height_min': profile.preferred_height_min,
            'preferred_height_max': profile.preferred_height_max,
            'preferred_ethnicity': profile.preferred_ethnicity,
            'preferred_eye_color': profile.preferred_eye_color,
            'preferred_hair_color': profile.preferred_hair_color,
            'preferred_education_level': profile.preferred_education_level,
            'genetic_screening_required': profile.genetic_screening_required,
            'preferred_age_min': profile.preferred_age_min,
            'preferred_age_max': profile.preferred_age_max,
            'preferred_occupation': profile.preferred_occupation,
            'preferred_religion': profile.preferred_religion,
            'importance_physical': profile.importance_physical,
            'importance_education': profile.importance_education,
            'importance_medical': profile.importance_medical,
            'importance_personality': profile.importance_personality,
            'special_requirements': profile.special_requirements,
        }

    async def send_error(self, message):
        """Send error message to client"""
        await self.send(text_data=json.dumps({
            'type': 'error',
            'message': message
        }))