from datetime import date
from decimal import Decimal
import io
import json
import os
import random
import re
import string
import threading
from typing import Set
from django.core.mail import send_mail
from django.conf import settings
from django.template.loader import render_to_string
from django.utils.html import strip_tags
import pandas as pd
from rest_framework.response import Response
from rest_framework import status, generics, permissions
from rest_framework.pagination import PageNumberPagination
from functools import wraps
import threading
import logging
from apis.models import Donor
from apis.services.embeddingsMatching import DonorMatchingEngine, EmbeddingService, MatchResult
from django.db import transaction
from decimal import Decimal, InvalidOperation
logger = logging.getLogger(__name__)

def send_verification_email(user, request=None):
    # Get domain - you can customize this based on your setup
    domain = request.get_host() if request else 'your-domain.com'
    protocol = 'https' if request and request.is_secure() else 'http'
    
    verification_url = f"{protocol}://{domain}/api/v1/verify-email/{user.email_verification_token}/"
    
    subject = 'Verify Your Email - Embryva'
    
    # HTML email template
    html_message = f"""
    <!DOCTYPE html>
    <html>
    <head>
        <meta charset="utf-8">
        <title>Email Verification</title>
        <style>
            body {{ font-family: Arial, sans-serif; line-height: 1.6; color: #333; }}
            .container {{ max-width: 600px; margin: 0 auto; padding: 20px; }}
            .header {{ background-color: #007bff; color: white; padding: 20px; text-align: center; }}
            .content {{ padding: 30px; background-color: #f9f9f9; }}
            .button {{ display: inline-block; padding: 12px 30px; background-color: #007bff; color: white; text-decoration: none; border-radius: 5px; margin: 20px 0; }}
            .footer {{ padding: 20px; text-align: center; color: #666; font-size: 14px; }}
        </style>
    </head>
    <body>
        <div class="container">
            <div class="header">
                <h1>Welcome to Embryva!</h1>
            </div>
            <div class="content">
                <h2>Hello {user.get_full_name() or user.email},</h2>
                <p>Thank you for signing up as a {user.get_user_type_display()}. To complete your registration and start using your account, please verify your email address.</p>
                <p>Click the button below to verify your email:</p>
                <a href="{verification_url}" class="button">Verify Email Address</a>
                <p>Or copy and paste this link into your browser:</p>
                <p><a href="{verification_url}">{verification_url}</a></p>
                <p><strong>Note:</strong> This verification link will expire in 24 hours.</p>
                <p>If you didn't create an account with us, please ignore this email.</p>
            </div>
            <div class="footer">
                <p>Best regards,<br>The Embryva Team</p>
            </div>
        </div>
    </body>
    </html>
    """
    
    # Plain text version
    plain_message = f"""
    Hello {user.get_full_name() or user.email},

    Thank you for signing up as a {user.get_user_type_display()}. To complete your registration and start using your account, please verify your email address.

    Click the link below to verify your email:
    {verification_url}

    Note: This verification link will expire in 24 hours.

    If you didn't create an account with us, please ignore this email.

    Best regards,
    The Embryva Team
    """
    
    try:
        send_mail(
            subject=subject,
            message=plain_message,
            html_message=html_message,
            from_email=settings.DEFAULT_FROM_EMAIL,
            recipient_list=[user.email],
            fail_silently=False,
        )
        return True
    except Exception as e:
        print(f"Failed to send verification email: {e}")
        return False

class CustomPageNumberPagination(PageNumberPagination):
    page_size = 10
    page_size_query_param = 'page_size'
    max_page_size = 100
    
    def get_paginated_response(self, data):
        return Response({
            'count': self.page.paginator.count,
            'total_pages': self.page.paginator.num_pages,
            'current_page': self.page.number,
            'page_size': self.page.paginator.per_page,
            'next': self.page.next_page_number() if self.page.has_next() else None,
            'previous': self.page.previous_page_number() if self.page.has_previous() else None,
            'results': data
        })
    
def generate_unique_donor_id(donor_type: str, existing_ids: Set[str]) -> str:
    prefix = 'EMB'  # Main prefix
    donor_type_prefix = {
        'sperm': 'SP',
        'egg': 'EG',
        'embryo': 'EM'
    }.get(str(donor_type).lower(), 'DN')  # Default prefix 'DN'

    # Loop to ensure the generated ID is unique
    while True:
        random_suffix = ''.join(random.choices(string.digits, k=6))
        potential_id = f"{prefix}{donor_type_prefix}{random_suffix}"
        
        # First, check against the fast in-memory set for the current batch.
        # Then, check against the database for all-time uniqueness.
        if potential_id not in existing_ids and not Donor.objects.filter(donor_id=potential_id).exists():
            
            # Add the new ID to the session set to prevent duplicates within the same file.
            existing_ids.add(potential_id)
            
            return potential_id
        
# Helper Functions
def validate_donor_row(row_data, row_number):
    errors = []
    
    required_fields = [
        'first_name', 'last_name', 'gender', 'date_of_birth', 
        'phone_number', 'blood_group'
    ]
    for field in required_fields:
        if pd.isna(row_data.get(field)) or str(row_data.get(field, '')).strip() == '':
            errors.append({
                'row': row_number,
                'field': field,
                'error': f'"{field}" is a required field and cannot be empty.'
            })

    # --- Donor Type Validation (from row) ---
    valid_donor_types = [choice[0] for choice in Donor.DONOR_TYPES]
    donor_type_value = str(row_data.get('donor_type', '')).strip().lower()
    if not donor_type_value:
        errors.append({
            'row': row_number,
            'field': 'donor_type',
            'error': '"donor_type" is a required field in the file.'
        })
    elif donor_type_value not in valid_donor_types:
        errors.append({
            'row': row_number,
            'field': 'donor_type',
            'error': f'Invalid donor_type "{row_data.get("donor_type")}". Must be one of: {", ".join(valid_donor_types)}.'
        })

    # --- Specific Field Content Validation ---
    
    # Validate gender
    gender_value = str(row_data.get('gender', '')).strip().lower()
    if gender_value and gender_value not in ['male', 'female']:
        errors.append({
            'row': row_number, 'field': 'gender', 'error': 'Gender must be "male" or "female".'
        })

    # # Validate blood group
    # valid_blood_groups = [choice[0] for choice in Donor.BLOOD_GROUPS]
    # blood_group_value = str(row_data.get('blood_group', '')).strip().upper()
    # if blood_group_value and blood_group_value not in valid_blood_groups:
    #     errors.append({
    #         'row': row_number, 'field': 'blood_group',
    #         'error': f'Blood group must be one of: {", ".join(valid_blood_groups)}.'
    #     })

    # Validate date of birth
    dob_value = row_data.get('date_of_birth')
    if dob_value and pd.notna(dob_value):
        try:
            dob = pd.to_datetime(str(dob_value)).date()
            today = date.today()
            age = today.year - dob.year - ((today.month, today.day) < (dob.month, dob.day))
            if age < 18:
                errors.append({'row': row_number, 'field': 'date_of_birth', 'error': 'Donor must be at least 18 years old.'})
            elif age > 65:
                errors.append({'row': row_number, 'field': 'date_of_birth', 'error': 'Donor age cannot exceed 65 years.'})
        except (ValueError, TypeError, pd.errors.OutOfBoundsDatetime):
            errors.append({'row': row_number, 'field': 'date_of_birth', 'error': 'Invalid date format. Use YYYY-MM-DD.'})

    # Validate numeric fields
    numeric_fields = {'height': 'Height', 'weight': 'Weight', 'number_of_children': 'Number of children'}
    for field, display_name in numeric_fields.items():
        value = row_data.get(field)
        if value is not None and str(value).strip() != '':
            try:
                num_value = float(str(value).strip())
                if num_value < 0:
                    errors.append({'row': row_number, 'field': field, 'error': f'{display_name} cannot be negative.'})
            except (ValueError, TypeError):
                errors.append({'row': row_number, 'field': field, 'error': f'{display_name} must be a valid number.'})

    # Validate boolean fields
    smoking_status = row_data.get('smoking_status')
    if smoking_status is not None and str(smoking_status).strip() != '':
        smoking_str = str(smoking_status).strip().lower()
        if smoking_str not in ['true', 'false', '1', '0', 'yes', 'no']:
            errors.append({'row': row_number, 'field': 'smoking_status', 'error': 'Smoking status must be TRUE/FALSE, YES/NO, or 1/0.'})
            
    return {'errors': errors}

def process_donor_data(row_data, clinic_user):
    """
    Processes and converts a single row of data to the Donor model format.
    """
    processed_data = {}
    # Complete field mapping from CSV/Excel column to Donor model field
    field_mapping = {
        'title': 'title', 'first_name': 'first_name', 'last_name': 'last_name', 'gender': 'gender',
        'date_of_birth': 'date_of_birth', 'phone_number': 'phone_number', 'email': 'email',
        'location': 'location', 'address': 'address', 'city': 'city', 'state': 'state',
        'country': 'country', 'postal_code': 'postal_code', 'donor_type': 'donor_type',
        'blood_group': 'blood_group', 'height': 'height', 'weight': 'weight',
        'eye_color': 'eye_color', 'hair_color': 'hair_color', 'skin_tone': 'skin_tone',
        'education_level': 'education_level', 'occupation': 'occupation', 'marital_status': 'marital_status',
        'religion': 'religion', 'ethnicity': 'ethnicity', 'medical_history': 'medical_history',
        'genetic_conditions': 'genetic_conditions', 'medications': 'medications', 'allergies': 'allergies',
        'smoking_status': 'smoking_status', 'alcohol_consumption': 'alcohol_consumption',
        'exercise_frequency': 'exercise_frequency', 'number_of_children': 'number_of_children',
        'family_medical_history': 'family_medical_history', 'personality_traits': 'personality_traits',
        'interests_hobbies': 'interests_hobbies', 'notes': 'notes'
    }

    for csv_field, model_field in field_mapping.items():
        if csv_field in row_data and pd.notna(row_data[csv_field]):
            value = str(row_data[csv_field]).strip()
            if value:
                processed_data[model_field] = value

    # --- Type Conversions and Specific Cleaning ---
    try:
        if 'date_of_birth' in processed_data:
            processed_data['date_of_birth'] = pd.to_datetime(processed_data['date_of_birth']).date()
        if 'height' in processed_data:
            processed_data['height'] = Decimal(processed_data['height'])
        if 'weight' in processed_data:
            processed_data['weight'] = Decimal(processed_data['weight'])
        if 'number_of_children' in processed_data:
            processed_data['number_of_children'] = int(float(processed_data['number_of_children']))
        if 'smoking_status' in processed_data:
            processed_data['smoking_status'] = processed_data['smoking_status'].lower() in ['true', '1', 'yes']
        if 'donor_type' in processed_data:
            processed_data['donor_type'] = processed_data['donor_type'].lower()
        if 'gender' in processed_data:
            processed_data['gender'] = processed_data['gender'].lower()
        if 'blood_group' in processed_data:
            processed_data['blood_group'] = processed_data['blood_group'].upper()
    except (ValueError, TypeError, InvalidOperation, pd.errors.OutOfBoundsDatetime) as e:
        # This should be caught by validation, but acts as a safeguard.
        # In a real scenario, you might log this conversion error.
        pass

    # --- Set Fields Not From File ---
    processed_data['clinic'] = clinic_user
    processed_data['created_by'] = clinic_user
    processed_data['availability_status'] = 'pending'
    processed_data['is_active'] = True
    
    return processed_data
        
def process_donor_import_logic(file, clinic_user):
    try:
        file_ext = os.path.splitext(file.name)[1].lower()
        file.seek(0)
        if file_ext == '.csv':
            df = pd.read_csv(io.StringIO(file.read().decode('utf-8-sig')))
        elif file_ext in ['.xlsx', '.xls']:
            df = pd.read_excel(file)
        elif file_ext == '.json':
            df = pd.DataFrame(json.loads(file.read().decode('utf-8-sig')))
        else:
            return {'success': False, 'message': 'Unsupported file format', 'status': 400}

        df.columns = df.columns.str.strip()
        if df.empty:
            return {'success': False, 'message': 'The uploaded file is empty.', 'status': 400}

        donors_to_create, embedding_data_list, failed_rows, generated_ids_in_session = [], [], [], set()

        for index, row in df.iterrows():
            row_number = index + 2
            row_data = {col: None if pd.isna(val) else val for col, val in row.items()}
            if all(v is None or str(v).strip() == '' for v in row_data.values()): continue
            validation_result = validate_donor_row(row_data, row_number)
            if validation_result['errors']:
                failed_rows.extend(validation_result['errors'])
                continue
            
            # Use the passed clinic_user object
            processed_data = process_donor_data(row_data, clinic_user)
            donor_id = generate_unique_donor_id(processed_data.get('donor_type', 'dn'), generated_ids_in_session)
            if 'phone_number' in row_data:
                processed_data['phone_number'] = clean_phone_number(row_data['phone_number'])
            processed_data['donor_id'] = donor_id
            
            donors_to_create.append(Donor(**processed_data))
            
            embedding_data = processed_data.copy()
            embedding_data['clinic_id'] = clinic_user.id
            embedding_data_list.append(embedding_data)

        if donors_to_create:
            with transaction.atomic():
                Donor.objects.bulk_create(donors_to_create)
            if embedding_data_list:
                embedding_service = EmbeddingService()
                threading.Thread(target=embedding_service.bulk_process_and_store_embeddings, args=(embedding_data_list,)).start()

        message = f'Import process finished. {len(donors_to_create)} donors queued for creation.'
        if failed_rows: message += f' {len(failed_rows)} rows failed validation.'

        return {
            'success': len(donors_to_create) > 0, 'message': message, 'imported_count': len(donors_to_create),
            'failed_count': len(failed_rows), 'errors': failed_rows, 'status': 200,
            'imported_donors': [{'donor_id': d.donor_id, 'name': d.full_name} for d in donors_to_create]
        }
    except Exception as e:
        logger.error(f"Error in donor import logic: {e}", exc_info=True)
        return {'success': False, 'message': f'An unexpected error occurred: {str(e)}', 'status': 500}


def execute_match_search_logic(profile_data):
    """
    Core logic for finding matching donors based on profile data.
    This is the complete and unabridged version.
    """
    try:
        embedding_service = EmbeddingService()
        matching_engine = DonorMatchingEngine()

        # 1. Generate Profile Embedding
        profile_text = embedding_service.create_profile_text(profile_data)
        profile_embedding = embedding_service.generate_embedding(profile_text)

        # 2. Semantic Search for Candidates
        similar_donors = embedding_service.search_similar_donors(
            profile_embedding=profile_embedding,
            top_k=100,  # Get a larger pool of candidates for detailed scoring
            donor_type_filter=profile_data.get('donor_type_preference')
        )

        if not similar_donors:
            return {
                'success': True,
                'message': 'No potential donor matches found in the initial search.',
                'matches': [],
                'status': 200
            }

        # 3. Detailed Filtering and Scoring
        match_results = []
        for similar_donor in similar_donors:
            try:
                # Pinecone returns metadata as a dict, get the donor_id
                donor_id = similar_donor['donor_id']
                donor = Donor.objects.select_related('clinic').get(donor_id=donor_id)

                # Create a comprehensive dictionary of the donor's attributes for scoring
                donor_data = {
                    'gender': donor.gender,
                    'donor_type': donor.donor_type,
                    'height': donor.height,
                    'eye_color': donor.eye_color,
                    'hair_color': donor.hair_color,
                    'ethnicity': donor.ethnicity,
                    'skin_tone': donor.skin_tone,
                    'education_level': donor.education_level,
                    'occupation': donor.occupation,
                    'blood_group': donor.blood_group,
                    'smoking_status': donor.smoking_status,
                    'alcohol_consumption': donor.alcohol_consumption,
                    'religion': donor.religion,
                    'marital_status': donor.marital_status,
                    'personality_traits': donor.personality_traits,
                    'interests_hobbies': donor.interests_hobbies,
                    'date_of_birth': donor.date_of_birth,
                    'genetic_conditions': donor.genetic_conditions,
                    'medical_history': donor.medical_history,
                    'location': donor.location,
                }

                # Calculate detailed rule-based score and compatibility breakdown
                detailed_score, matched_attrs, compat_scores = matching_engine.calculate_detailed_match_score(
                    donor_data, profile_data
                )

                # Combine scores: 60% rule-based + 40% semantic similarity
                final_score = (detailed_score * 0.6) + (similar_donor['similarity_score'] * 0.4)

                # Generate a human-readable explanation for the match
                ai_explanation = matching_engine.generate_ai_explanation(
                    donor_data, profile_data, matched_attrs, final_score
                )

                # Store the comprehensive result
                match_results.append(MatchResult(
                    donor_id=donor.donor_id,
                    clinic_id=str(donor.clinic.id),
                    match_score=final_score,
                    matched_attributes=matched_attrs,
                    ai_explanation=ai_explanation,
                    compatibility_scores=compat_scores
                ))

            except Donor.DoesNotExist:
                logger.warning(f"Donor {similar_donor.get('donor_id')} from semantic search not found in database. Skipping.")
                continue
            except Exception as e:
                logger.error(f"Error processing donor {similar_donor.get('donor_id', 'N/A')} during detailed scoring: {e}")
                continue

        # 4. Sort and Filter Final Results
        match_results.sort(key=lambda x: x.match_score, reverse=True)

        # Filter for matches with a score of at least 50% and limit to top 50
        high_quality_matches = [m for m in match_results if m.match_score >= 0.50][:50]

        # 5. Format the Response Payload
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

        return {
            'success': True,
            'message': f'Found {len(formatted_matches)} high-quality matching donors.',
            'matches': formatted_matches,
            'status': 200
        }

    except Exception as e:
        logger.error(f"Critical error in match search logic: {e}", exc_info=True)
        return {'success': False, 'message': str(e), 'status': 500}
    
def clean_phone_number(phone_number):
    """
    Clean and validate phone number to ensure it fits within database constraints.
    """
    if not phone_number:
        return None
    
    # Convert to string and strip whitespace
    phone_str = str(phone_number).strip()
    
    # Remove common formatting characters
    cleaned = re.sub(r'[^\d+\-\s()]', '', phone_str)
    
    # Truncate if too long (adjust length as needed)
    max_length = 17  # or whatever your database field allows
    if len(cleaned) > max_length:
        cleaned = cleaned[:max_length]
    
    return cleaned

def prepare_donor_data_for_embedding(donor_instance):
    """
    Prepare comprehensive donor data for embedding generation.
    This ensures all relevant fields are included for better matching.
    """
    return {
        'donor_id': donor_instance.donor_id,
        'gender': donor_instance.gender,
        'donor_type': donor_instance.donor_type,
        'age': donor_instance.age,
        'height': float(donor_instance.height) if donor_instance.height else None,
        'weight': float(donor_instance.weight) if donor_instance.weight else None,
        'eye_color': donor_instance.eye_color,
        'hair_color': donor_instance.hair_color,
        'skin_tone': donor_instance.skin_tone,
        'ethnicity': donor_instance.ethnicity,
        'education_level': donor_instance.education_level,
        'occupation': donor_instance.occupation,
        'blood_group': donor_instance.blood_group,
        'smoking_status': donor_instance.smoking_status,
        'alcohol_consumption': donor_instance.alcohol_consumption,
        'exercise_frequency': donor_instance.exercise_frequency,
        'religion': donor_instance.religion,
        'marital_status': donor_instance.marital_status,
        'location': donor_instance.location,
        'city': donor_instance.city,
        'state': donor_instance.state,
        'country': donor_instance.country,
        'date_of_birth': donor_instance.date_of_birth,
        'personality_traits': donor_instance.personality_traits or [],
        'interests_hobbies': donor_instance.interests_hobbies or [],
        'genetic_conditions': donor_instance.genetic_conditions,
        'medical_history': donor_instance.medical_history,
        'family_medical_history': donor_instance.family_medical_history,
        'allergies': donor_instance.allergies,
        'medications': donor_instance.medications,
        'availability_status': donor_instance.availability_status,
        'number_of_children': donor_instance.number_of_children,
    }


def prepare_metadata_for_pinecone(donor_instance):
    """
    Prepare metadata for Pinecone storage.
    Filters out null values to prevent Pinecone errors.
    """
    metadata = {
        'donor_id': donor_instance.donor_id,
        'donor_type': donor_instance.donor_type,
        'gender': donor_instance.gender,
        'age': donor_instance.age,
        'blood_group': donor_instance.blood_group,
        'availability_status': donor_instance.availability_status,
        'location': donor_instance.location,
        'city': donor_instance.city,
        'state': donor_instance.state,
        'country': donor_instance.country,
        'created_at': donor_instance.created_at.isoformat(),
        'updated_at': donor_instance.updated_at.isoformat(),
    }
    
    # Add optional fields only if they have values
    optional_fields = {
        'education_level': donor_instance.education_level,
        'ethnicity': donor_instance.ethnicity,
        'occupation': donor_instance.occupation,
        'marital_status': donor_instance.marital_status,
        'religion': donor_instance.religion,
        'eye_color': donor_instance.eye_color,
        'hair_color': donor_instance.hair_color,
        'skin_tone': donor_instance.skin_tone,
        'smoking_status': str(donor_instance.smoking_status),
        'alcohol_consumption': donor_instance.alcohol_consumption,
        'exercise_frequency': donor_instance.exercise_frequency,
    }
    
    # Add numeric fields
    if donor_instance.height:
        metadata['height'] = float(donor_instance.height)
    if donor_instance.weight:
        metadata['weight'] = float(donor_instance.weight)
    if donor_instance.number_of_children is not None:
        metadata['number_of_children'] = donor_instance.number_of_children
    
    # Add list fields (convert to string for Pinecone)
    if donor_instance.personality_traits:
        metadata['personality_traits'] = str(donor_instance.personality_traits)
    if donor_instance.interests_hobbies:
        metadata['interests_hobbies'] = str(donor_instance.interests_hobbies)
    
    # Filter out None values and empty strings
    filtered_metadata = {}
    for key, value in {**metadata, **optional_fields}.items():
        if value is not None and value != '' and value != 'None':
            filtered_metadata[key] = value
    
    return filtered_metadata