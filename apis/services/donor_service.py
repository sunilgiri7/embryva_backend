import pandas as pd
import io
import json
import logging
from typing import List, Dict, Any, Tuple
from ..models import Donor, FertilityProfile
from ..utils import validate_donor_row, process_donor_data, generate_unique_donor_id, clean_phone_number
from .embeddingsMatching import EmbeddingService, DonorMatchingEngine, MatchResult
from ..tasks import bulk_create_donors_and_embeddings_task

logger = logging.getLogger(__name__)

class DonorImportService:
    """Handles the logic for importing donors from a file."""

    def __init__(self, file, clinic_user):
        self.file = file
        self.clinic_user = clinic_user

    def process_import(self) -> Dict[str, Any]:
        try:
            df = self._read_file()
            if df.empty:
                return {'success': False, 'message': 'The uploaded file is empty.', 'status': 400}

            processed_donors, failed_rows = self._validate_and_prepare_data(df)

            if processed_donors:
                bulk_create_donors_and_embeddings_task.delay(processed_donors, str(self.clinic_user.id))

            message = f'Import process started. {len(processed_donors)} donors queued for creation.'
            if failed_rows:
                message += f' {len(failed_rows)} rows failed validation.'

            return {
                'success': True,
                'message': message,
                'queued_count': len(processed_donors),
                'failed_count': len(failed_rows),
                'errors': failed_rows,
                'status': 202
            }
        except Exception as e:
            logger.error(f"Error in DonorImportService: {e}", exc_info=True)
            return {'success': False, 'message': f'An unexpected error occurred: {str(e)}', 'status': 500}

    def _read_file(self) -> pd.DataFrame:
        file_ext = self.file.name.split('.')[-1].lower()
        self.file.seek(0)
        content = self.file.read()

        if file_ext == 'csv':
            return pd.read_csv(io.StringIO(content.decode('utf-8-sig')))
        elif file_ext in ['xlsx', 'xls']:
            return pd.read_excel(io.BytesIO(content))
        elif file_ext == 'json':
            return pd.DataFrame(json.loads(content.decode('utf-8-sig')))
        else:
            raise ValueError('Unsupported file format')

    def _validate_and_prepare_data(self, df: pd.DataFrame) -> Tuple[List[Dict], List[Dict]]:
        processed_list, failed_rows = [], []
        generated_ids = set()

        for index, row in df.iterrows():
            row_data = {col: val for col, val in row.items() if pd.notna(val)}
            if not row_data: continue

            validation = validate_donor_row(row_data, index + 2)
            if validation['errors']:
                failed_rows.extend(validation['errors'])
                continue

            processed = process_donor_data(row_data, self.clinic_user)
            processed['donor_id'] = generate_unique_donor_id(processed.get('donor_type', 'dn'), generated_ids)
            if 'phone_number' in processed:
                processed['phone_number'] = clean_phone_number(processed['phone_number'])
            
            processed.pop('clinic')
            processed.pop('created_by')
            
            processed_list.append(processed)

        return processed_list, failed_rows


class DonorMatchingService:
    """Encapsulates the logic for finding donor matches."""

    def __init__(self, fertility_profile: FertilityProfile):
        self.profile = fertility_profile
        self.embedding_service = EmbeddingService()
        self.matching_engine = DonorMatchingEngine()

    def find_matches(self) -> Dict[str, Any]:
        """
        Orchestrates the process of finding, scoring, and ranking donor matches.
        """
        try:
            profile_data = self._get_profile_data()
            profile_text = self.embedding_service.create_profile_text(profile_data)
            profile_embedding = self.embedding_service.generate_embedding(profile_text)

            # 1. Semantic search to get initial candidates
            similar_donors = self.embedding_service.search_similar_donors(
                profile_embedding=profile_embedding,
                top_k=100,  # Widen the net for better detailed scoring
                donor_type_filter=self.profile.donor_type_preference
            )
            if not similar_donors:
                return {'success': True, 'message': 'No potential donors found.', 'matches': []}

            # 2. Detailed scoring and ranking
            match_results = self._score_and_rank_donors(similar_donors, profile_data)
            
            # 3. Format for API response
            formatted_matches = self._format_results(match_results)

            return {
                'success': True,
                'message': f'Found {len(formatted_matches)} high-quality matching donors.',
                "Total Matches": len(formatted_matches),
                'matches': formatted_matches
            }
        except Exception as e:
            logger.error(f"Critical error in DonorMatchingService for profile {self.profile.id}: {e}", exc_info=True)
            # Re-raise to be caught by the view layer for a 500 response
            raise

    def _get_profile_data(self) -> Dict[str, Any]:
        """
        Creates a dictionary from the fertility profile model instance
        to be used by the matching engine.
        """
        return {
            'donor_type_preference': self.profile.donor_type_preference,
            'location': self.profile.location,
            'preferred_height_min': self.profile.preferred_height_min,
            'preferred_height_max': self.profile.preferred_height_max,
            'preferred_ethnicity': self.profile.preferred_ethnicity,
            'preferred_eye_color': self.profile.preferred_eye_color,
            'preferred_hair_color': self.profile.preferred_hair_color,
            'preferred_education_level': self.profile.preferred_education_level,
            'genetic_screening_required': self.profile.genetic_screening_required,
            'preferred_age_min': self.profile.preferred_age_min,
            'preferred_age_max': self.profile.preferred_age_max,
            'preferred_occupation': self.profile.preferred_occupation,
            'preferred_religion': self.profile.preferred_religion,
            'importance_physical': self.profile.importance_physical,
            'importance_education': self.profile.importance_education,
            'importance_medical': self.profile.importance_medical,
            'importance_personality': self.profile.importance_personality,
            'special_requirements': self.profile.special_requirements,
        }

    def _score_and_rank_donors(self, similar_donors: List, profile_data: Dict) -> List[MatchResult]:
        """
        Fetches full donor data, calculates a hybrid score (semantic + rule-based),
        and generates an AI explanation for each potential match.
        """
        match_results = []
        
        # Get all relevant donor IDs from the semantic search at once to reduce DB hits
        donor_ids = [d['donor_id'] for d in similar_donors]
        donors_from_db = Donor.objects.filter(donor_id__in=donor_ids, is_active=True).select_related('clinic')
        
        # Create a lookup map for quick access
        donor_map = {d.donor_id: d for d in donors_from_db}
        
        for similar_donor in similar_donors:
            donor = donor_map.get(similar_donor['donor_id'])
            if not donor:
                logger.warning(f"Donor {similar_donor['donor_id']} from semantic search not found in database. Skipping.")
                continue

            try:
                # Prepare a dictionary of the donor's attributes for scoring
                donor_data = {
                    'gender': donor.gender, 'donor_type': donor.donor_type,
                    'height': donor.height, 'eye_color': donor.eye_color, 'hair_color': donor.hair_color,
                    'ethnicity': donor.ethnicity, 'education_level': donor.education_level, 'occupation': donor.occupation,
                    'blood_group': donor.blood_group, 'smoking_status': donor.smoking_status, 'religion': donor.religion,
                    'date_of_birth': donor.date_of_birth, 'genetic_conditions': donor.genetic_conditions,
                    'personality_traits': donor.personality_traits, 'interests_hobbies': donor.interests_hobbies,
                }

                # Calculate detailed rule-based score and compatibility breakdown
                detailed_score, matched_attrs, compat_scores = self.matching_engine.calculate_detailed_match_score(
                    donor_data, profile_data
                )

                # **Combine scores: 60% rule-based + 40% semantic similarity**
                final_score = (detailed_score * 0.6) + (similar_donor['similarity_score'] * 0.4)

                # Generate a human-readable explanation for the match
                ai_explanation = self.matching_engine.generate_ai_explanation(
                    donor_data, profile_data, matched_attrs, final_score
                )

                match_results.append(MatchResult(
                    donor_id=donor.donor_id,
                    clinic_id=str(donor.clinic.id),
                    match_score=final_score,
                    matched_attributes=matched_attrs,
                    ai_explanation=ai_explanation,
                    compatibility_scores=compat_scores
                ))

            except Exception as e:
                logger.error(f"Error processing donor {donor.donor_id} during detailed scoring: {e}", exc_info=True)
                continue

        # Sort results by the final combined score in descending order
        match_results.sort(key=lambda x: x.match_score, reverse=True)
        
        return match_results


    def _format_results(self, match_results: List[MatchResult]) -> List[Dict]:
        """
        Formats the final list of MatchResult objects into the JSON structure
        expected by the API response.
        """
        # Filter for matches with a score of at least 50% and limit to the top 50
        high_quality_matches = [m for m in match_results if m.match_score >= 0.50][:50]
        
        formatted_matches = []
        for match in high_quality_matches:
            formatted_matches.append({
                'donor_reference_id': match.donor_id,
                'clinic_reference_id': match.clinic_id,
                'match_percentage': round(match.match_score * 100, 1),
                'ai_explanation': match.ai_explanation,
                'matched_attributes_summary': list(match.matched_attributes.keys()),
                'compatibility_score': {
                    'overall': round(match.match_score * 100, 1),
                    'physical': round(match.compatibility_scores.get('physical', 0), 1),
                    'educational': round(match.compatibility_scores.get('educational', 0), 1),
                    'demographic': round(match.compatibility_scores.get('demographic', 0), 1),
                    'medical': round(match.compatibility_scores.get('medical', 0), 1),
                }
            })
            
        return formatted_matches