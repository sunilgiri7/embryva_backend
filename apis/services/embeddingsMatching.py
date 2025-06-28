import logging
from typing import Dict, List, Any, Optional, Tuple
from datetime import datetime, date
from dataclasses import dataclass
from django.conf import settings
from pinecone import Pinecone, ServerlessSpec
from sentence_transformers import SentenceTransformer
from sklearn.metrics.pairwise import cosine_similarity
logging.basicConfig(level=logging.INFO)
logger = logging.getLogger(__name__)

class EmbeddingService:
    def __init__(self):
        self.model_name = "all-MiniLM-L6-v2"
        self.model = None
        self.pc = None  # Pinecone client instance
        self.index_name = "embryva"
        self.index = None

    def initialize_pinecone(self):
        if not self.pc:
            try:
                self.pc = Pinecone(api_key='pcsk_62ucZK_FnxEpEu4Ld6cm9FRM4Hb5WBPAoHshbjggHGKotaDRwVnRbDEY5ty4XjpU8u4CpM')

                if self.index_name not in self.pc.list_indexes().names():
                    self.pc.create_index(
                        name=self.index_name,
                        dimension=384,
                        metric="cosine",
                        spec=ServerlessSpec(
                            cloud="aws",
                            region=settings.PINECONE_ENVIRONMENT  # e.g., "us-west-2"
                        )
                    )

                self.index = self.pc.Index(self.index_name)
                logger.info("Pinecone initialized successfully")

            except Exception as e:
                logger.error(f"Failed to initialize Pinecone: {e}")
                raise
    def initialize_model(self):
        """Initialize the sentence transformer model"""
        if self.model is None:
            try:
                from torch import device
                self.model = SentenceTransformer(self.model_name, device='cpu')  # <-- Force CPU
                logger.info(f"Initialized embedding model on CPU: {self.model_name}")
            except Exception as e:
                logger.error(f"Failed to initialize embedding model: {e}")
                raise
    
    def create_donor_text(self, donor_data: Dict) -> str:
        """Create comprehensive text representation of donor for embedding"""
        text_parts = []
        
        # Basic info
        if donor_data.get('gender'):
            text_parts.append(f"Gender: {donor_data['gender']}")
        if donor_data.get('donor_type'):
            text_parts.append(f"Donor type: {donor_data['donor_type']}")
        
        # Physical attributes
        physical_attrs = []
        if donor_data.get('height'):
            physical_attrs.append(f"height {donor_data['height']}cm")
        if donor_data.get('eye_color'):
            physical_attrs.append(f"{donor_data['eye_color']} eyes")
        if donor_data.get('hair_color'):
            physical_attrs.append(f"{donor_data['hair_color']} hair")
        if donor_data.get('ethnicity'):
            physical_attrs.append(f"{donor_data['ethnicity']} ethnicity")
        if donor_data.get('skin_tone'):
            physical_attrs.append(f"{donor_data['skin_tone']} skin")
        
        if physical_attrs:
            text_parts.append(f"Physical: {', '.join(physical_attrs)}")
        
        # Education and occupation
        if donor_data.get('education_level'):
            text_parts.append(f"Education: {donor_data['education_level']}")
        if donor_data.get('occupation'):
            text_parts.append(f"Occupation: {donor_data['occupation']}")
        
        # Medical and lifestyle
        medical_parts = []
        if donor_data.get('blood_group'):
            medical_parts.append(f"blood group {donor_data['blood_group']}")
        if donor_data.get('smoking_status'):
            medical_parts.append(f"smoking: {donor_data['smoking_status']}")
        if donor_data.get('alcohol_consumption'):
            medical_parts.append(f"alcohol: {donor_data['alcohol_consumption']}")
        
        if medical_parts:
            text_parts.append(f"Medical: {', '.join(medical_parts)}")
        
        # Demographics
        demo_parts = []
        if donor_data.get('religion'):
            demo_parts.append(f"religion: {donor_data['religion']}")
        if donor_data.get('marital_status'):
            demo_parts.append(f"marital status: {donor_data['marital_status']}")
        
        if demo_parts:
            text_parts.append(f"Demographics: {', '.join(demo_parts)}")
        
        # Personality and interests
        if donor_data.get('personality_traits'):
            text_parts.append(f"Personality: {donor_data['personality_traits']}")
        if donor_data.get('interests_hobbies'):
            text_parts.append(f"Interests: {donor_data['interests_hobbies']}")
        
        # Calculate age if date_of_birth is available
        if donor_data.get('date_of_birth'):
            try:
                if isinstance(donor_data['date_of_birth'], str):
                    birth_date = datetime.strptime(donor_data['date_of_birth'], '%Y-%m-%d').date()
                else:
                    birth_date = donor_data['date_of_birth']
                
                today = date.today()
                age = today.year - birth_date.year - ((today.month, today.day) < (birth_date.month, birth_date.day))
                text_parts.append(f"Age: {age} years")
            except:
                pass
        
        return ". ".join(text_parts)
    
    def create_profile_text(self, profile_data: Dict) -> str:
        """Create text representation of parent's preferences"""
        text_parts = []
        
        # Basic preferences
        if profile_data.get('donor_type_preference'):
            text_parts.append(f"Looking for: {profile_data['donor_type_preference']} donor")
        
        # Physical preferences
        physical_prefs = []
        if profile_data.get('preferred_height_min') or profile_data.get('preferred_height_max'):
            height_range = f"{profile_data.get('preferred_height_min', 'any')}cm to {profile_data.get('preferred_height_max', 'any')}cm"
            physical_prefs.append(f"height {height_range}")
        
        if profile_data.get('preferred_ethnicity'):
            physical_prefs.append(f"{profile_data['preferred_ethnicity']} ethnicity")
        if profile_data.get('preferred_eye_color'):
            physical_prefs.append(f"{profile_data['preferred_eye_color']} eyes")
        if profile_data.get('preferred_hair_color'):
            physical_prefs.append(f"{profile_data['preferred_hair_color']} hair")
        
        if physical_prefs:
            text_parts.append(f"Physical preferences: {', '.join(physical_prefs)}")
        
        # Education preference
        if profile_data.get('preferred_education_level'):
            text_parts.append(f"Education preference: {profile_data['preferred_education_level']}")
        
        # Age preferences
        if profile_data.get('preferred_age_min') or profile_data.get('preferred_age_max'):
            age_range = f"{profile_data.get('preferred_age_min', 'any')} to {profile_data.get('preferred_age_max', 'any')} years"
            text_parts.append(f"Age preference: {age_range}")
        
        # Other preferences
        if profile_data.get('preferred_occupation'):
            text_parts.append(f"Occupation preference: {profile_data['preferred_occupation']}")
        if profile_data.get('preferred_religion'):
            text_parts.append(f"Religion preference: {profile_data['preferred_religion']}")
        
        # Importance weights
        importance_parts = []
        if profile_data.get('importance_physical', 0) > 7:
            importance_parts.append("physical attributes very important")
        if profile_data.get('importance_education', 0) > 7:
            importance_parts.append("education very important")
        if profile_data.get('importance_medical', 0) > 7:
            importance_parts.append("medical history very important")
        
        if importance_parts:
            text_parts.append(f"Priorities: {', '.join(importance_parts)}")
        
        # Special requirements
        if profile_data.get('special_requirements'):
            text_parts.append(f"Special requirements: {profile_data['special_requirements']}")
        
        return ". ".join(text_parts)
    
    def generate_embedding(self, text: str) -> List[float]:
        """Generate embedding for given text"""
        self.initialize_model()
        try:
            embedding = self.model.encode(text)
            return embedding.tolist()
        except Exception as e:
            logger.error(f"Failed to generate embedding: {e}")
            raise
    
    def store_donor_embedding(self, donor_id: str, clinic_id: str, embedding: List[float], metadata: Dict):
        """Store donor embedding in Pinecone"""
        self.initialize_pinecone()
        try:
            index = self.index

            # Create unique vector ID
            vector_id = f"{clinic_id}_{donor_id}"

            # Store embedding with metadata
            index.upsert(vectors=[{
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

            logger.info(f"Stored embedding for donor {donor_id}")

        except Exception as e:
            logger.error(f"Failed to store donor embedding: {e}")
            raise
    
    def search_similar_donors(self, profile_embedding: List[float], top_k: int = 20, 
                          donor_type_filter: str = None) -> List[Dict]:
        """Search for similar donors using profile embedding"""
        self.initialize_pinecone()
        try:
            index = self.index

            # Build filter for donor type if specified
            filter_dict = {}
            if donor_type_filter and donor_type_filter.lower() != 'both':
                filter_dict["donor_type"] = donor_type_filter

            # Search similar vectors
            search_response = index.query(
                vector=profile_embedding,
                top_k=top_k,
                include_metadata=True,
                filter=filter_dict or None
            )

            results = []
            for match in search_response.matches:
                results.append({
                    "donor_id": match.metadata.get("donor_id"),
                    "clinic_id": match.metadata.get("clinic_id"),
                    "similarity_score": float(match.score),
                    "metadata": match.metadata
                })

            return results

        except Exception as e:
            logger.error(f"Failed to search similar donors: {e}")
            raise

# ================ MATCHING ENGINE ================

@dataclass
class MatchResult:
    donor_id: str
    clinic_id: str
    match_score: float
    matched_attributes: Dict[str, Any]
    ai_explanation: str

class DonorMatchingEngine:
    """Main engine for donor matching logic"""
    
    def __init__(self):
        self.embedding_service = EmbeddingService()
    
    def calculate_detailed_match_score(self, donor_data: Dict, profile_data: Dict) -> Tuple[float, Dict]:
        """Calculate detailed match score with specific attribute matching"""
        matched_attributes = {}
        scores = []
        weights = []
        
        # Physical attribute matching
        physical_score, physical_matches = self._match_physical_attributes(donor_data, profile_data)
        if physical_matches:
            matched_attributes.update(physical_matches)
            scores.append(physical_score)
            weights.append(profile_data.get('importance_physical', 5))
        
        # Education matching
        education_score, education_matches = self._match_education(donor_data, profile_data)
        if education_matches:
            matched_attributes.update(education_matches)
            scores.append(education_score)
            weights.append(profile_data.get('importance_education', 5))
        
        # Age matching
        age_score, age_matches = self._match_age(donor_data, profile_data)
        if age_matches:
            matched_attributes.update(age_matches)
            scores.append(age_score)
            weights.append(5)  # Default weight for age
        
        # Demographic matching
        demo_score, demo_matches = self._match_demographics(donor_data, profile_data)
        if demo_matches:
            matched_attributes.update(demo_matches)
            scores.append(demo_score)
            weights.append(3)  # Lower weight for demographics
        
        # Medical/lifestyle matching
        medical_score, medical_matches = self._match_medical(donor_data, profile_data)
        if medical_matches:
            matched_attributes.update(medical_matches)
            scores.append(medical_score)
            weights.append(profile_data.get('importance_medical', 5))
        
        # Calculate weighted average
        if scores and weights:
            total_weight = sum(weights)
            weighted_score = sum(s * w for s, w in zip(scores, weights)) / total_weight
        else:
            weighted_score = 0.0
        
        return weighted_score, matched_attributes
    
    def _match_physical_attributes(self, donor_data: Dict, profile_data: Dict) -> Tuple[float, Dict]:
        """Match physical attributes"""
        matches = {}
        score = 0.0
        total_checks = 0
        
        # Height matching
        if profile_data.get('preferred_height_min') or profile_data.get('preferred_height_max'):
            donor_height = donor_data.get('height')
            if donor_height:
                height_min = profile_data.get('preferred_height_min', 0)
                height_max = profile_data.get('preferred_height_max', 300)
                
                if height_min <= donor_height <= height_max:
                    matches['height'] = f"Height {donor_height}cm matches preference ({height_min}-{height_max}cm)"
                    score += 1.0
                total_checks += 1
        
        # Ethnicity matching
        if profile_data.get('preferred_ethnicity') and donor_data.get('ethnicity'):
            if profile_data['preferred_ethnicity'].lower() == donor_data['ethnicity'].lower():
                matches['ethnicity'] = f"Ethnicity ({donor_data['ethnicity']}) matches preference"
                score += 1.0
            total_checks += 1
        
        # Eye color matching
        if profile_data.get('preferred_eye_color') and donor_data.get('eye_color'):
            if profile_data['preferred_eye_color'].lower() == donor_data['eye_color'].lower():
                matches['eye_color'] = f"Eye color ({donor_data['eye_color']}) matches preference"
                score += 1.0
            total_checks += 1
        
        # Hair color matching
        if profile_data.get('preferred_hair_color') and donor_data.get('hair_color'):
            if profile_data['preferred_hair_color'].lower() in donor_data['hair_color'].lower():
                matches['hair_color'] = f"Hair color ({donor_data['hair_color']}) matches preference"
                score += 1.0
            total_checks += 1
        
        final_score = score / total_checks if total_checks > 0 else 0.0
        return final_score, matches
    
    def _match_education(self, donor_data: Dict, profile_data: Dict) -> Tuple[float, Dict]:
        """Match education levels"""
        matches = {}
        
        if not profile_data.get('preferred_education_level') or not donor_data.get('education_level'):
            return 0.0, matches
        
        education_hierarchy = {
            'high_school': 1,
            'bachelors': 2,
            'masters': 3,
            'doctorate': 4,
            'professional': 4
        }
        
        preferred_level = education_hierarchy.get(profile_data['preferred_education_level'], 0)
        donor_level = education_hierarchy.get(donor_data['education_level'], 0)
        
        if donor_level >= preferred_level:
            matches['education'] = f"Education level ({donor_data['education_level']}) meets or exceeds preference"
            return 1.0, matches
        else:
            return 0.5, matches
    
    def _match_age(self, donor_data: Dict, profile_data: Dict) -> Tuple[float, Dict]:
        """Match age preferences"""
        matches = {}
        
        if not donor_data.get('date_of_birth'):
            return 0.0, matches
        
        # Calculate donor age
        try:
            if isinstance(donor_data['date_of_birth'], str):
                birth_date = datetime.strptime(donor_data['date_of_birth'], '%Y-%m-%d').date()
            else:
                birth_date = donor_data['date_of_birth']
            
            today = date.today()
            age = today.year - birth_date.year - ((today.month, today.day) < (birth_date.month, birth_date.day))
            
            age_min = profile_data.get('preferred_age_min', 18)
            age_max = profile_data.get('preferred_age_max', 65)
            
            if age_min <= age <= age_max:
                matches['age'] = f"Age {age} years matches preference ({age_min}-{age_max} years)"
                return 1.0, matches
            else:
                return 0.3, matches
                
        except:
            return 0.0, matches
    
    def _match_demographics(self, donor_data: Dict, profile_data: Dict) -> Tuple[float, Dict]:
        """Match demographic preferences"""
        matches = {}
        score = 0.0
        total_checks = 0
        
        # Religion matching
        if profile_data.get('preferred_religion') and donor_data.get('religion'):
            if profile_data['preferred_religion'].lower() == donor_data['religion'].lower():
                matches['religion'] = f"Religion ({donor_data['religion']}) matches preference"
                score += 1.0
            total_checks += 1
        
        # Occupation matching (partial match allowed)
        if profile_data.get('preferred_occupation') and donor_data.get('occupation'):
            if profile_data['preferred_occupation'].lower() in donor_data['occupation'].lower() or \
               donor_data['occupation'].lower() in profile_data['preferred_occupation'].lower():
                matches['occupation'] = f"Occupation ({donor_data['occupation']}) relates to preference"
                score += 1.0
            total_checks += 1
        
        final_score = score / total_checks if total_checks > 0 else 0.0
        return final_score, matches
    
    def _match_medical(self, donor_data: Dict, profile_data: Dict) -> Tuple[float, Dict]:
        """Match medical and lifestyle factors"""
        matches = {}
        score = 0.0
        total_checks = 0
        
        # Genetic screening requirement
        if profile_data.get('genetic_screening_required', True):
            # Assume genetic screening is done if no genetic conditions are reported
            if not donor_data.get('genetic_conditions') or donor_data['genetic_conditions'].lower() in ['none', 'nil', '']:
                matches['genetic_screening'] = "No reported genetic conditions"
                score += 1.0
            total_checks += 1
        
        # Smoking status (prefer non-smokers)
        if donor_data.get('smoking_status'):
            if donor_data['smoking_status'].lower() in ['never', 'non-smoker', 'no']:
                matches['smoking'] = "Non-smoker status"
                score += 1.0
            total_checks += 1
        
        final_score = score / total_checks if total_checks > 0 else 0.0
        return final_score, matches
    
    def generate_ai_explanation(self, donor_data: Dict, profile_data: Dict, 
                              matched_attributes: Dict, match_score: float) -> str:
        """Generate AI explanation for the match"""
        explanations = []
        
        # Start with overall compatibility
        if match_score >= 0.8:
            explanations.append("This donor shows excellent compatibility with your preferences.")
        elif match_score >= 0.6:
            explanations.append("This donor shows good compatibility with your preferences.")
        else:
            explanations.append("This donor shows moderate compatibility with your preferences.")
        
        # Highlight key matches
        key_matches = []
        if 'height' in matched_attributes:
            key_matches.append("physical characteristics")
        if 'education' in matched_attributes:
            key_matches.append("educational background")
        if 'age' in matched_attributes:
            key_matches.append("age preferences")
        if 'ethnicity' in matched_attributes:
            key_matches.append("ethnic background")
        if 'genetic_screening' in matched_attributes:
            key_matches.append("medical screening standards")
        
        if key_matches:
            explanations.append(f"Key alignment areas include: {', '.join(key_matches)}.")
        
        # Add specific highlights
        if 'education' in matched_attributes and 'age' in matched_attributes:
            explanations.append("The donor's educational achievements and age align well with your criteria.")
        
        if len(matched_attributes) >= 3:
            explanations.append("Multiple compatibility factors suggest this could be a strong match for your family planning goals.")
        
        return " ".join(explanations)