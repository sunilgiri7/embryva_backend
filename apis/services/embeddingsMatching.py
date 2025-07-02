# services.py

import logging
from typing import Dict, List, Any, Optional, Tuple
from datetime import datetime, date
from dataclasses import dataclass
from django.conf import settings
from pinecone import Pinecone, ServerlessSpec
from sentence_transformers import SentenceTransformer
import uuid # Import uuid

logging.basicConfig(level=logging.INFO)
logger = logging.getLogger(__name__)


# ================== EMBEDDING SERVICE (REFINED) ==================

class EmbeddingService:
    def __init__(self):
        # Using a more powerful model can yield better semantic results
        self.model_name = "all-mpnet-base-v2" 
        self.dimension = 768 # Dimension for the new model
        self.model = None
        self.pc = None
        self.index_name = "embryva-v2" # New index for new model
        self.index = None

    def initialize_pinecone(self):
        if not self.pc:
            try:
                # IMPORTANT: Store your API key in Django settings, not in code.
                self.pc = Pinecone(api_key=settings.PINECONE_API_KEY)

                if self.index_name not in self.pc.list_indexes().names():
                    self.pc.create_index(
                        name=self.index_name,
                        dimension=self.dimension, # Updated dimension
                        metric="cosine",
                        spec=ServerlessSpec(
                            cloud="aws",
                            region=settings.PINECONE_ENVIRONMENT
                        )
                    )
                self.index = self.pc.Index(self.index_name)
                logger.info("Pinecone initialized successfully for index '%s'.", self.index_name)
            except Exception as e:
                logger.error(f"Failed to initialize Pinecone: {e}")
                raise

    def initialize_model(self):
        if self.model is None:
            try:
                from torch import device
                # Use CPU for broader compatibility
                self.model = SentenceTransformer(self.model_name, device='cpu')
                logger.info(f"Initialized embedding model on CPU: {self.model_name}")
            except Exception as e:
                logger.error(f"Failed to initialize embedding model: {e}")
                raise

    def create_donor_text(self, donor_data: Dict) -> str:
        """Create a natural language representation of a donor for embedding."""
        text_parts = []

        # Age and Type
        try:
            birth_date = donor_data.get('date_of_birth')
            age = 'unknown age'
            if birth_date:
                today = date.today()
                age_val = today.year - birth_date.year - ((today.month, today.day) < (birth_date.month, birth_date.day))
                age = f"{age_val} years old"
            text_parts.append(f"A {age} {donor_data.get('gender', '')} {donor_data.get('donor_type', 'donor')}.")
        except Exception:
            text_parts.append(f"A {donor_data.get('gender', '')} {donor_data.get('donor_type', 'donor')}.")

        # Physical Description
        physical_desc = f"Physically, they have a height of {donor_data.get('height')}cm, with {donor_data.get('eye_color', '')} eyes and {donor_data.get('hair_color', '')} hair."
        if donor_data.get('ethnicity'):
            physical_desc += f" Their ethnicity is {donor_data.get('ethnicity')}."
        text_parts.append(physical_desc)

        # Background
        if donor_data.get('education_level'):
            text_parts.append(f"They have achieved an education level of {donor_data.get('education_level')} and work as an {donor_data.get('occupation', 'unknown')}.")
        if donor_data.get('religion'):
            text_parts.append(f"Their religion is {donor_data.get('religion')}.")

        # Lifestyle and Health
        lifestyle = f"Health-wise, their blood group is {donor_data.get('blood_group', 'unknown')}."
        if donor_data.get('smoking_status') is not None:
            lifestyle += f" They are a {'non-smoker' if not donor_data['smoking_status'] else 'smoker'}."
        text_parts.append(lifestyle)

        # Personality
        if donor_data.get('personality_traits'):
            traits = ', '.join(donor_data['personality_traits'])
            text_parts.append(f"Key personality traits include: {traits}.")
        if donor_data.get('interests_hobbies'):
            interests = ', '.join(donor_data['interests_hobbies'])
            text_parts.append(f"Their interests and hobbies are: {interests}.")

        return " ".join(text_parts)

    def create_profile_text(self, profile_data: Dict) -> str:
        """Create a natural language representation of a parent's preferences."""
        text_parts = [f"A parent is looking for a {profile_data.get('donor_type_preference', 'any type')} donor."]

        # Physical Preferences
        physical_prefs = []
        if profile_data.get('preferred_height_min') and profile_data.get('preferred_height_max'):
            physical_prefs.append(f"height between {profile_data['preferred_height_min']}cm and {profile_data['preferred_height_max']}cm")
        if profile_data.get('preferred_ethnicity'):
            physical_prefs.append(f"ethnicity of {profile_data['preferred_ethnicity']}")
        if profile_data.get('preferred_eye_color'):
            physical_prefs.append(f"{profile_data['preferred_eye_color']} eyes")
        if profile_data.get('preferred_hair_color'):
            physical_prefs.append(f"{profile_data['preferred_hair_color']} hair")

        if physical_prefs:
            text_parts.append(f"They have a strong preference for physical traits, including: {', '.join(physical_prefs)}.")
        
        # Other Preferences
        if profile_data.get('preferred_education_level'):
            text_parts.append(f"An educational background of at least a {profile_data['preferred_education_level']} is important.")
        if profile_data.get('preferred_age_min') and profile_data.get('preferred_age_max'):
            text_parts.append(f"The preferred age range for the donor is {profile_data['preferred_age_min']} to {profile_data['preferred_age_max']} years.")
        
        # Importance
        priorities = []
        if profile_data.get('importance_physical', 0) > 7: priorities.append("physical traits")
        if profile_data.get('importance_education', 0) > 7: priorities.append("education")
        if profile_data.get('importance_medical', 0) > 7: priorities.append("medical history")
        if priorities:
            text_parts.append(f"They place high importance on {', '.join(priorities)}.")

        if profile_data.get('special_requirements'):
            text_parts.append(f"Additional notes include: {profile_data['special_requirements']}")

        return " ".join(text_parts)
    
    def generate_embedding(self, text: str) -> List[float]:
        self.initialize_model()
        try:
            embedding = self.model.encode(text, convert_to_tensor=False)
            return embedding.tolist()
        except Exception as e:
            logger.error(f"Failed to generate embedding: {e}")
            raise

    def store_donor_embedding(self, donor_id: str, clinic_id: str, embedding: List[float], metadata: Dict):
        self.initialize_pinecone()
        vector_id = f"{clinic_id}_{donor_id}"
        self.index.upsert(vectors=[{
            "id": vector_id,
            "values": embedding,
            "metadata": {
                "donor_id": donor_id,
                "clinic_id": clinic_id,
                "donor_type": metadata.get("donor_type"),
                "created_at": datetime.now().isoformat(),
                **metadata
            }
        }])
        logger.info(f"Stored embedding for donor {donor_id} from clinic {clinic_id}")

    def search_similar_donors(self, profile_embedding: List[float], top_k: int = 50, donor_type_filter: str = None) -> List[Dict]:
        self.initialize_pinecone()
        filter_dict = {}
        if donor_type_filter and donor_type_filter.lower() != 'both':
            filter_dict["donor_type"] = donor_type_filter
        
        search_response = self.index.query(
            vector=profile_embedding,
            top_k=top_k,
            include_metadata=True,
            filter=filter_dict or None
        )
        
        return [{
            "donor_id": match.metadata.get("donor_id"),
            "clinic_id": match.metadata.get("clinic_id"),
            "similarity_score": float(match.score),
            "metadata": match.metadata
        } for match in search_response.matches]


# ================== MATCHING ENGINE (UPGRADED) ==================

@dataclass
class MatchResult:
    donor_id: str
    clinic_id: str
    match_score: float
    matched_attributes: Dict[str, Any]
    ai_explanation: str
    compatibility_scores: Dict[str, float]


class DonorMatchingEngine:
    def __init__(self):
        self.embedding_service = EmbeddingService()

    def _calculate_age(self, birth_date):
        if not birth_date:
            return None
        today = date.today()
        return today.year - birth_date.year - ((today.month, today.day) < (birth_date.month, birth_date.day))

    def calculate_detailed_match_score(self, donor_data: Dict, profile_data: Dict) -> Tuple[float, Dict, Dict]:
        matched_attributes = {}
        scores = []
        weights = []
        compatibility_scores = {'physical': 0.0, 'educational': 0.0, 'medical': 0.0, 'demographic': 0.0}

        # Match Physical Attributes
        physical_score, physical_matches, total_physical_checks = self._match_physical_attributes(donor_data, profile_data)
        if total_physical_checks > 0:
            matched_attributes.update(physical_matches)
            scores.append(physical_score)
            weights.append(profile_data.get('importance_physical', 5))
            compatibility_scores['physical'] = physical_score * 100

        # Match Education
        education_score, education_matches, total_edu_checks = self._match_education(donor_data, profile_data)
        if total_edu_checks > 0:
            matched_attributes.update(education_matches)
            scores.append(education_score)
            weights.append(profile_data.get('importance_education', 5))
            compatibility_scores['educational'] = education_score * 100

        # Match Demographics (Age, Religion, etc.)
        demo_score, demo_matches, total_demo_checks = self._match_demographics(donor_data, profile_data)
        if total_demo_checks > 0:
            matched_attributes.update(demo_matches)
            scores.append(demo_score)
            weights.append(4) # Default weight
            compatibility_scores['demographic'] = demo_score * 100
        
        # Match Medical
        medical_score, medical_matches, total_medical_checks = self._match_medical(donor_data, profile_data)
        if total_medical_checks > 0:
            matched_attributes.update(medical_matches)
            scores.append(medical_score)
            weights.append(profile_data.get('importance_medical', 8)) # Medical is important
            compatibility_scores['medical'] = medical_score * 100

        # Calculate final weighted average
        total_weight = sum(weights)
        if not scores or total_weight == 0:
            return 0.0, {}, compatibility_scores
        
        weighted_score = sum(s * w for s, w in zip(scores, weights)) / total_weight
        return weighted_score, matched_attributes, compatibility_scores

    def _match_physical_attributes(self, donor, profile):
        matches, score, checks = {}, 0.0, 0
        if profile.get('preferred_height_min') and profile.get('preferred_height_max') and donor.get('height'):
            checks += 1
            if profile['preferred_height_min'] <= donor['height'] <= profile['preferred_height_max']:
                score += 1; matches['height'] = f"Height ({donor['height']}cm) is within your preferred range."
        if profile.get('preferred_ethnicity') and donor.get('ethnicity'):
            checks += 1
            if profile['preferred_ethnicity'].lower() == donor['ethnicity'].lower():
                score += 1; matches['ethnicity'] = f"Matches your preferred ethnicity ({donor['ethnicity']})."
        if profile.get('preferred_eye_color') and donor.get('eye_color'):
            checks += 1
            if profile['preferred_eye_color'].lower() == donor['eye_color'].lower():
                score += 1; matches['eye_color'] = f"Matches your preferred eye color ({donor['eye_color']})."
        if profile.get('preferred_hair_color') and donor.get('hair_color'):
            checks += 1
            if profile['preferred_hair_color'].lower() == donor['hair_color'].lower():
                score += 1; matches['hair_color'] = f"Matches your preferred hair color ({donor['hair_color']})."
        return (score / checks if checks > 0 else 0.0, matches, checks)

    def _match_education(self, donor, profile):
        matches, score, checks = {}, 0.0, 0
        if profile.get('preferred_education_level') and donor.get('education_level'):
            checks += 1
            hierarchy = {'high_school': 1, 'bachelors': 2, 'masters': 3, 'doctorate': 4, 'professional': 4}
            if hierarchy.get(donor['education_level'], 0) >= hierarchy.get(profile['preferred_education_level'], 0):
                score += 1; matches['education'] = f"Education level ({donor['education_level']}) meets your preference."
        return (score / checks if checks > 0 else 0.0, matches, checks)

    def _match_demographics(self, donor, profile):
        matches, score, checks = {}, 0.0, 0
        donor_age = self._calculate_age(donor.get('date_of_birth'))
        if profile.get('preferred_age_min') and profile.get('preferred_age_max') and donor_age:
            checks += 1
            if profile['preferred_age_min'] <= donor_age <= profile['preferred_age_max']:
                score += 1; matches['age'] = f"Age ({donor_age}) is within your preferred range."
        if profile.get('preferred_religion') and donor.get('religion'):
            checks += 1
            if profile['preferred_religion'].lower() == donor['religion'].lower():
                score += 1; matches['religion'] = f"Matches your preferred religion ({donor['religion']})."
        return (score / checks if checks > 0 else 0.0, matches, checks)

    def _match_medical(self, donor, profile):
        matches, score, checks = {}, 0.0, 0
        if profile.get('genetic_screening_required'):
            checks += 1
            if not donor.get('genetic_conditions') or donor.get('genetic_conditions', '').lower() in ['none', 'nil']:
                score += 1; matches['genetic_screening'] = "Passes genetic screening requirements (no reported conditions)."
        return (score / checks if checks > 0 else 0.0, matches, checks)

    def generate_ai_explanation(self, donor_data: Dict, profile_data: Dict, matched_attributes: Dict, match_score: float) -> str:
        """Generates a dynamic, narrative explanation for the match."""
        score_percent = round(match_score * 100)
        
        # Opening Statement
        if score_percent >= 90:
            opening = f"This donor is an **excellent match** with an overall compatibility of **{score_percent}%**."
        elif score_percent >= 75:
            opening = f"This donor is a **strong match** with an overall compatibility of **{score_percent}%**."
        else:
            opening = f"This donor shows **good potential** with a compatibility score of **{score_percent}%**."

        # Strengths of the Match
        strengths = []
        if 'height' in matched_attributes or 'ethnicity' in matched_attributes or 'eye_color' in matched_attributes:
            strengths.append("key physical characteristics")
        if 'education' in matched_attributes:
            strengths.append("educational background")
        if 'age' in matched_attributes:
            strengths.append("age preference")
        if 'genetic_screening' in matched_attributes:
            strengths.append("medical criteria")

        if not strengths:
            summary = "The match is primarily based on a strong semantic similarity in your overall profiles."
        else:
            summary = f"The high compatibility is driven by alignment in {', '.join(strengths)}."

        # Detailed Highlights
        highlights = "<ul>"
        for key, value in matched_attributes.items():
            highlights += f"<li><strong>{key.replace('_', ' ').title()}:</strong> {value}</li>"
        highlights += "</ul>"

        return f"<p>{opening} {summary}</p><h4>Match Highlights:</h4>{highlights}"