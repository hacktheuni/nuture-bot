from sqlalchemy.orm import Session
from uuid import UUID
from typing import Optional, List, Dict, Any
from datetime import datetime, timezone, timedelta
from sqlalchemy import text
from sqlalchemy.sql.dml import ReturningUpdate

from app.models.database_models import OTPVerification, QuestionType, User, UserRole, Authentication, AuthenticationProvider, RefreshToken, OnboardingQuestion, QuestionChoice, MemoryType, Memory, MessageType, Model, ModelProvider, Message, OnboardingAnswers, OTPPurpose
from app.schemas.onboarding import OnboardingAnswer
from app.utils.auth import hash_refresh_token, verify_password, hash_password
from app.utils.otp import hash_otp
from app.core.config import settings

class DBService:
    def __init__(self, session_session: Session):
        self.session = session_session

    def get_user_by_email(self, email: str):
        try:
            return self.session.query(User).filter(User.email==email).first()
        except Exception as e:
            print(f"Error getting user by email: {e}")
            return None

    def get_user_by_id(self, user_id: UUID):
        try:
            return self.session.query(User).filter(User.id==user_id).first()
        except Exception as e:
            print(f"Error getting user by ID: {e}")
            return None

    def get_all_admins(self):
        try:
            return self.session.query(User).filter(User.role==UserRole.admin).all()
        except Exception as e:
            print(f"Error getting all admins: {e}")
            return []

    def get_all_users(self):
        try:
            return self.session.query(User).filter(User.role==UserRole.user).all()
        except Exception as e:
            print(f"Error getting all users: {e}")
            return []

    def create_user_with_email_auth(self, email: str, hashed_password: str, first_name: str, last_name: str, role: UserRole = UserRole.user, is_verified: bool = False, is_onboarded: bool = False):
        try:
            user = User(email=email, first_name=first_name, last_name=last_name, role=role, is_onboarded=is_onboarded, is_verified=is_verified)
            self.session.add(user)
            self.session.flush()

            user_auth = Authentication(user_id=user.id, provider=AuthenticationProvider.email, provider_user_id=None, hashed_password=hashed_password)
            self.session.add(user_auth)
            self.session.commit()

            return user
        except Exception as e:
            self.session.rollback()
            print(f"Error creating user with email auth: {e}")
            raise e

    def create_user_with_oauth_auth(self, email: str, provider: str, provider_user_id: str, first_name: str, last_name: str):
        try:
            user = User(email=email, first_name=first_name, last_name=last_name, role=UserRole.user)
            self.session.add(user)
            self.session.flush()

            user_auth = Authentication(user_id=user.id, provider=provider, provider_user_id=provider_user_id, hashed_password=None)
            self.session.add(user_auth)
            self.session.commit()

            return user
        except Exception as e:
            self.session.rollback()
            print(f"Error creating user with OAuth auth: {e}")
            raise e

    def get_user_email_auth(self, email: str):
        try:
            return self.session.query(Authentication).join(User).filter(User.email == email, Authentication.provider == AuthenticationProvider.email).first()
        except Exception as e:
            print(f"Error getting user email auth: {e}")
            return None

    def get_user_oauth_auth(self, provider: str, provider_user_id: str):
        try:
            return self.session.query(Authentication).filter(Authentication.provider==provider, Authentication.provider_user_id==provider_user_id).first()
        except Exception as e:
            print(f"Error getting user OAuth auth: {e}")
            return None

    def link_oauth_provider_to_user(self, user_id: UUID, provider: str, provider_user_id: str):
        try:
            existing_user_auth = self.session.query(Authentication).filter(Authentication.provider==provider, Authentication.provider_user_id==provider_user_id).first()

            if existing_user_auth:
                raise Exception(f"{provider.capitalize()} account is already linked to another user account")

            user_oauth = Authentication(
                user_id=user_id,
                provider=provider,
                provider_user_id=provider_user_id,
                hashed_password=None
            )

            self.session.add(user_oauth)
            self.session.commit()
            return True
        except Exception as e:
            self.session.rollback()
            print(f"Error linking OAuth provider: {e}")
            raise e

    def unlink_oauth_provider_from_user(self, user_id: UUID, provider: str):
        try:
            if provider not in ['google', 'github']:
                raise Exception(f"Unsupported OAuth provider: {provider}")
            
            # Check if user exists
            user = self.get_user_by_id(user_id)
            if not user:
                raise Exception("User not found")
            
            # Check if link exists
            link = self.session.query(Authentication).filter(
                Authentication.user_id==user_id, 
                Authentication.provider==provider
            ).first()

            if not link:
                raise Exception(f"{provider.capitalize()} account is not linked to this user")

            # Get all authentication methods for the user
            total_auth = self.session.query(Authentication).filter(
                Authentication.user_id==user_id
            ).all()

            # Check if user has email/password authentication
            email_auth = self.session.query(Authentication).filter(
                Authentication.user_id==user_id,
                Authentication.provider == AuthenticationProvider.email,
                Authentication.hashed_password.isnot(None)
            ).first()
            
            has_password = email_auth is not None

            # Get count of OAuth providers (excluding email)
            oauth_providers = [auth for auth in total_auth if auth.provider != AuthenticationProvider.email]
            
            # Rule 1: If user only has OAuth providers (no password), prevent unlinking
            if not has_password and len(oauth_providers) == 1:
                raise Exception("Cannot unlink. Please set up an email password first before unlinking OAuth providers.")
   
            # Rule 2: Cannot unlink the last remaining authentication method
            if len(total_auth) <= 1:
                raise Exception("Cannot unlink the last remaining authentication method. Please add another authentication method first.")

            # Safe to unlink - user has email/password OR multiple OAuth providers
            self.session.delete(link)
            self.session.commit()
            return True
        except Exception as e:
            self.session.rollback()
            print(f"Error unlinking OAuth provider: {e}")
            raise e

    def login_or_register_with_oauth(self, email: str, first_name: Optional[str], last_name: Optional[str], provider: str, provider_user_id: str):
        try:
            # Check if this OAuth account is already linked to a user
            oauth_auth = self.session.query(Authentication).filter(
                Authentication.provider==provider, 
                Authentication.provider_user_id==provider_user_id
            ).first()

            if oauth_auth:
                user = self.session.query(User).filter(User.id==oauth_auth.user_id).first()
                
                if not user:
                    raise Exception("User not found for existing OAuth authentication")
                
                if not user.is_active:
                    raise Exception("User account is deactivated")
                
                return {
                    "id": user.id,
                    "email": user.email,
                    "role": user.role
                }
            
            # Check if a user with this email already exists
            existing_user = self.session.query(User).filter(User.email==email).first()

            if existing_user:
                if not existing_user.is_active:
                    raise Exception("User account is deactivated")

                # Link the OAuth provider to the existing user
                self.link_oauth_provider_to_user(existing_user.id, provider, provider_user_id)
                
                return {
                    "id": existing_user.id,
                    "email": existing_user.email,
                    "role": existing_user.role
                }
            
            # No existing user found, create new user with OAuth
            else:
                user = self.create_user_with_oauth_auth(email, provider, provider_user_id, first_name, last_name)

                return {
                    "id": user.id,
                    "email": user.email,
                    "role": user.role
                }
        except Exception as e:
            self.session.rollback()
            print(f"Error in login_or_register_with_oauth: {e}")
            raise e

    def store_refresh_token(self, user_id: str, plain_token: str):
        try:
            hashed_token = hash_refresh_token(plain_token)
            expires_at = datetime.now(timezone.utc) + timedelta(days=settings.REFRESH_TOKEN_EXPIRE_DAYS)
            token = RefreshToken(
                user_id=user_id,
                token=hashed_token,
                expires_at=expires_at
            )
            self.session.add(token)
            self.session.commit()
            return True
        except Exception as e:
            self.session.rollback()
            print(f"Error storing refresh token: {e}")
            raise Exception(f"Failed to store refresh token: {str(e)}")
        
    def use_refresh_token(self, plain_token: str):
        hashed_token = hash_refresh_token(plain_token)
        now = datetime.now(timezone.utc)
        
        token_record = self.session.query(RefreshToken).filter(
            RefreshToken.token == hashed_token,
            RefreshToken.expires_at > now,
            RefreshToken.revoked == False
        ).first()

        if not token_record:
            return None # Token is invalid, expired, or already used

        # Revoke the old token to prevent reuse (this is the rotation part)
        token_record.revoked = True
        self.session.commit()
        
        return str(token_record.user_id)

    def delete_all_refresh_tokens_for_user(self, user_id: UUID):
        try:
            deleted = self.session.query(RefreshToken).filter(
                RefreshToken.user_id == user_id
            ).delete(synchronize_session=False)
            self.session.commit()
            return deleted
        except:
            return 0

    def store_otp(self, user_id: UUID, otp: str, purpose: OTPPurpose = OTPPurpose.verification):
        try:
            hashed_otp = hash_otp(otp)
            # Password reset OTPs expire in 15 minutes, verification OTPs expire in 5 minutes
            expiry_minutes = 5
            expires_at = datetime.now(timezone.utc) + timedelta(minutes=expiry_minutes)
            otp_record = OTPVerification(
                user_id=user_id,
                code=hashed_otp,
                purpose=purpose,
                expires_at=expires_at,
            )
            self.session.add(otp_record)
            self.session.commit()
            return True
        except Exception as e:
            self.session.rollback()
            print(f"Error storing OTP: {e}")
            raise Exception(f"Failed to store OTP: {str(e)}")

    def verify_otp(self, user_id: UUID, otp: str, purpose: OTPPurpose = OTPPurpose.verification):
        try:
            hashed_otp = hash_otp(otp)
            now = datetime.now(timezone.utc)
            
            otp_record = self.session.query(OTPVerification).filter(
                OTPVerification.user_id == user_id,
                OTPVerification.code == hashed_otp,
                OTPVerification.purpose == purpose,
                OTPVerification.expires_at > now,
            ).first()
            
            if not otp_record:
                raise Exception("Invalid or expired OTP")
            
            user = self.get_user_by_id(user_id)
            if not user:
                raise Exception("User not found")
            
            # For verification purpose, activate the user
            if purpose == OTPPurpose.verification:
                user.is_active = True
            
            self.session.commit()
            return user
        except Exception as e:
            self.session.rollback()
            print(f"Error verifying OTP: {e}")
            raise e

    def reset_user_password(self, user_id: UUID, hashed_password: str):
        try:
            user_email_auth = self.session.query(Authentication).filter(Authentication.user_id==user_id, Authentication.provider==AuthenticationProvider.email).first()

            if not user_email_auth:
                raise Exception("Email authentication not found for this user. Cannot reset password.")

            user_email_auth.hashed_password = hashed_password
            self.session.commit()
            return True
        except Exception as e:
            self.session.rollback()
            print(f"Error resetting user password: {e}")
            raise e
        

    def activate_user_by_id(self, user_id: UUID):
        try:
            user_data = self.get_user_by_id(user_id)

            if user_data:
                user_data.is_active = True
                self.session.commit()
                return user_data

            return None
        except Exception as e:
            self.session.rollback()
            print(f"Error activating user: {e}")
            return None


    def deactivate_user_by_id(self, user_id: UUID):
        try:
            user_data = self.get_user_by_id(user_id)

            if user_data:
                user_data.is_active = False
                self.session.commit()
                return user_data

            return None
        except Exception as e:
            self.session.rollback()
            print(f"Error deactivating user: {e}")
            return None


    def update_user_by_id(self, user_id: UUID, first_name: str, last_name: str):
        try:
            user_data = self.get_user_by_id(user_id)

            if user_data:
                user_data.first_name = first_name
                user_data.last_name = last_name
                self.session.commit()
                return user_data
            
            return None
        except Exception as e:
            self.session.rollback()
            print(f"Error updating user: {e}")
            return None

    
    def delete_user_by_id(self, user_id: UUID):
        try:
            user_data = self.get_user_by_id(user_id)

            if not user_data:
                raise Exception(f"User with ID {user_id} not found")

            self.session.delete(user_data)
            self.session.commit()
            return True
        except Exception as e:
            self.session.rollback()
            print(f"Error deleting user: {e}")
            raise e

    def change_user_password(self, user_id: UUID, current_password: str, new_password: str):
        try:
            user_email_auth = self.session.query(Authentication).filter(Authentication.user_id==user_id, Authentication.provider==AuthenticationProvider.email).first()

            if not user_email_auth:
                raise Exception("Email authentication not found for this user. Cannot change password.")

            verify_pass = verify_password(current_password, user_email_auth.hashed_password)

            if not verify_pass:
                raise Exception("Current password is incorrect")

            hashed_password = hash_password(new_password)
            user_email_auth.hashed_password = hashed_password
            self.session.commit()
            return True
        except Exception as e:
            self.session.rollback()
            print(f"Error changing user password: {e}")
            raise e


    def get_active_onboarding_questions(self):
        try:
            return self.session.query(OnboardingQuestion).filter(OnboardingQuestion.is_active==True).all()
        except Exception as e:
            print(f"Error getting active onboarding questions: {e}")
            return []

    def get_question_by_text(self, question_text: str):
        try:
            return self.session.query(OnboardingQuestion).filter(OnboardingQuestion.question_text==question_text).first()
        except Exception as e:
            print(f"Error getting question by text: {e}")
            return None

    def create_onboarding_question(
            self, 
            question_text: str, 
            question_type: QuestionType,
            question_order: Optional[int] = None,
            choices: Optional[List[str]] = None  
        ):
            try:
                
                new_question = OnboardingQuestion(
                    question_text=question_text,
                    question_type=question_type,
                    question_order=question_order
                )
                self.session.add(new_question)
                self.session.flush() 
                
            
                if choices and question_type == QuestionType.mcq:
                    for choice_text in choices:
                        new_choice = QuestionChoice(
                            question_id=new_question.id,
                            choice_text=choice_text
                        )
                        self.session.add(new_choice)

                self.session.commit()
                self.session.refresh(new_question)
                return new_question
            
            except Exception as e:
                self.session.rollback()
                print(f"Error creating onboarding question: {e}")
                raise e

    def update_onboarding_question(
        self,
        question_id: str,
        updates: Dict[str, Any],
    ) -> Optional[OnboardingQuestion]:
        try:
            # Find the question to update
            question = self.session.query(OnboardingQuestion).filter(OnboardingQuestion.id == question_id).first()
            print(question.id)
            if not question:
                return None
            
            if "remove_choice_ids" in updates and updates["remove_choice_ids"]:
                
                delete_ids = updates["remove_choice_ids"]
                
                if not delete_ids:
                    pass  
                else:
                    valid_choice_ids = {c.id for c in question.choices}
                    invalid_ids = set(delete_ids) - valid_choice_ids

                    if invalid_ids:
                        raise ValueError(f"Cannot delete choices not belonging to this question: {list(invalid_ids)}")

                    deleted_count = self.session.query(QuestionChoice).filter(
                        QuestionChoice.id.in_(delete_ids),
                        QuestionChoice.question_id == question.id
                    ).delete(synchronize_session=False)

                    if deleted_count != len(delete_ids):
                        print(f"Warning: Expected to delete {len(delete_ids)} choices, but deleted {deleted_count}")

                    self.session.refresh(question)

            if "choices" in updates:
                new_choices_data = updates.pop("choices")
                existing_choices = {str(c.id): c for c in question.choices}
                # updated_choice_ids = set()

                for choice_data in new_choices_data:
                    choice_id = str(choice_data.get("id")) if choice_data.get("id") else None
                    
                    if choice_id in existing_choices:
                        existing_choices[choice_id].choice_text = choice_data["choice_text"]
                        # updated_choice_ids.add(choice_id)
                    else:
                        new_choice = QuestionChoice(
                            question_id=question.id,
                            choice_text=choice_data["choice_text"]
                        )
                        self.session.add(new_choice)
                                
            updates.pop("choices", None)   
            updates.pop("remove_choice_ids", None)

            for key, value in updates.items():
                setattr(question, key, value)
                

            
            users_answer = self.session.query(OnboardingAnswers).filter(OnboardingAnswers.question_id==question_id).delete(synchronize_session=False)
            self.session.commit()
            self.session.refresh(question)
            return question
        except Exception as e:
            self.session.rollback()
            print(f"Error updating onboarding question: {e}")
            return None

    def delete_question_by_id(self, question_id: UUID):
        try:
            question_data = self.session.query(OnboardingQuestion).filter(OnboardingQuestion.id==question_id).first()

            if question_data:
                self.session.delete(question_data)
                self.session.commit()
                return True
            
            return False
        except Exception as e:
            self.session.rollback()
            print(f"Error deleting question: {e}")
            return False

    def get_all_questions(self):
        """Get all onboarding questions (active and inactive)"""
        try:
            return self.session.query(OnboardingQuestion).order_by(OnboardingQuestion.question_order.asc()).all()
        except Exception as e:
            print(f"Error getting all questions: {e}")
            return []

    def reorder_questions(self, ordered_ids: List[UUID]):
        """Reorder questions based on provided list of IDs"""
        try:
            for order, question_id in enumerate(ordered_ids, start=1):
                question = self.session.query(OnboardingQuestion).filter(OnboardingQuestion.id==question_id).first()
                if question:
                    question.question_order = order
            
            self.session.commit()
            return True
        except Exception as e:
            self.session.rollback()
            print(f"Error reordering questions: {e}")
            return False

    def save_onboarding_answers(self, user_id: str, answers: List[OnboardingAnswer]) -> Dict[str, Any]:
        saved=[]
        errors=[]
        
        for answer_data in answers:
            question_id = answer_data.question_id
            answer_value = answer_data.answer # This could be a string, a UUID, or a list of UUIDs
                  
            try:
                question = self.session.query(OnboardingQuestion).filter(OnboardingQuestion.id == question_id).first()
                
                if not question:
                    errors.append({"question_id": question_id, "error": "Question not found"})
                    continue
                    
                if not getattr(question, "is_active", True):
                    errors.append({"question_id": question_id, "error": "Question is not active"})
                    continue
                
                question_type = question.question_type
                
                all_choices = (
                    self.session.query(QuestionChoice.id, QuestionChoice.choice_text)
                    .filter(QuestionChoice.question_id == question.id)
                    .all()
                )
                
                choice_id_to_text = {str(row.id): row.choice_text for row in all_choices}
                total_choices_count = len(choice_id_to_text)

                final_answer_text = None
                
                # TEXT question
                if question_type == QuestionType.text:
                    if isinstance(answer_value, list) or (isinstance(answer_value, (dict, UUID)) and not isinstance(answer_value, str)):
                        errors.append({"question_id": question_id, "error": "Expected a text string answer for text question"})
                        continue
                    if answer_value is None or (isinstance(answer_value, str) and answer_value.strip() == ""):
                        errors.append({"question_id": question_id, "error": "Text answer cannot be empty"})
                        continue
                    final_answer_text = str(answer_value).strip()
                    
                # MCQ single choice
                elif question_type == QuestionType.mcq:
                    if isinstance(answer_value, list):
                        errors.append({"question_id": question_id, "error": "MCQ question expects a single choice"})
                        continue
                    try:
                        choice_id = str(UUID(str(answer_value)))
                    except Exception:
                        errors.append({"question_id": question_id, "error": "MCQ answer must be a valid UUID choice id"})
                        continue

                    if choice_id not in choice_id_to_text:
                        errors.append({"question_id": question_id, "error": "Provided choice id does not belong to this question"})
                        continue

                    final_answer_text = choice_id_to_text[choice_id]
                    
                elif question_type == QuestionType.multiple_choice:
                    if not isinstance(answer_value, list):
                        errors.append({"question_id": question_id, "error": "Multiple Choice question expects single or mutliple options"})
                        continue

                    normalized_choice_ids = []
                    invalid_uuid_ids = []
                    for c in answer_value:
                        try:
                            normalized_choice_ids.append(str(UUID(str(c))))
                        except Exception:
                            invalid_uuid_ids.append(str(c))

                    if invalid_uuid_ids:
                        errors.append({"question_id": question_id, "error": f"Invalid UUIDs in choices: {invalid_uuid_ids}"})
                        continue

                    normalized_choice_ids = list(dict.fromkeys(normalized_choice_ids))

                    if len(normalized_choice_ids) > total_choices_count:
                        errors.append({"question_id": question_id, "error": "Number of selected choices exceeds available options"})
                        continue

                    invalid_for_question = [cid for cid in normalized_choice_ids if cid not in choice_id_to_text]
                    if invalid_for_question:
                        errors.append({"question_id": question_id, "error": f"Selected option does not belong to this question"})
                        continue

                    selected_texts = [choice_id_to_text[cid] for cid in normalized_choice_ids]
                    final_answer_text = ", ".join(selected_texts)

                else:
                    errors.append({"question_id": question_id, "error": f"Unsupported question type: {question_type}"})
                    continue
                
                try:
                    user_answer = OnboardingAnswers(
                        user_id=user_id,
                        question_id=question_id,
                        answer=final_answer_text
                    )
                    user_memory = Memory(
                        user_id=user_id,
                        key=question.question_text,
                        value=final_answer_text,
                        type=MemoryType.onboarding
                    )

                    self.session.add(user_answer)
                    self.session.add(user_memory)
                    self.session.commit()
                    saved.append(question_id)
                except Exception as e_up:
                    errors.append({"question_id": question_id, "error": f"DB save error: {str(e_up)}"})
                    try:
                        self.session.rollback()
                    except Exception:
                        pass
                    continue
    
            except Exception as e:
                errors.append({"question_id": question_id, "error": f"Unexpected error: {str(e)}"})
                try:
                    self.session.rollback()
                except Exception:
                    pass
                continue
        
        if saved:
            try:
                user = self.session.query(User).filter(User.id==user_id).first()
                user.is_onboarded = True
                self.session.commit()
            except Exception as e_flag:
                errors.append({"user_flag_error": f"Failed to update is_onboarded: {str(e_flag)}"})
                try:
                    self.session.rollback()
                except Exception:
                    pass
                
            
        return {"saved": saved, "errors": errors}
     
    
    def get_memories_by_user(self, user_id: UUID):
        return self.session.query(Memory).filter(Memory.user_id==user_id).all()


    def store_memeory(self, user_id: UUID, key: str, value: str):

        new_memory = Memory(user_id=user_id, key=key, value=value, type=MemoryType.ai)

        if new_memory:
            self.session.add(new_memory)
            self.session.commit()
            return new_memory
        
        return False

    def get_user_onboarding_answers(self, user_id: UUID) -> List[Dict[str, Any]]:
        try:
            answers = (
                self.session.query(OnboardingAnswers.question_id, OnboardingAnswers.answer)
                .filter(OnboardingAnswers.user_id == user_id)
                .all()
            )
            return [{"question_id": str(row.question_id), "answer": row.answer} for row in answers]
        except Exception as e:
            print(f"Error fetching user onboarding answers: {e}")
            return []

        
    def get_ids_for_uploaded_file(self, collection_id: str, filename: str) -> Optional[List[str]]:
        try:
            # Execute raw SQL directly since this table is not in our standard models
            sql = text("""
                SELECT id
                FROM langchain_pg_embedding
                WHERE collection_id = :collection_id
                AND cmetadata->>'source' = :filename
            """ \
            )
            result = self.session.execute(sql, {
                "collection_id": collection_id,
                "filename": filename
            })

            return [row[0] for row in result.fetchall()]
        except Exception as e:
            print(f"Error getting IDs for uploaded file: {e}")
            return None       
        
    def get_ids_for_chat_history(self, collection_id: str, user_id: str):
        try:
            # Execute raw SQL directly since this table is not in our standard models
            sql = text("""
                SELECT id
                FROM langchain_pg_embedding
                WHERE collection_id = :collection_id
                AND cmetadata->>'user_id' = :user_id
            """ \
            )
            result = self.session.execute(sql, {
                "collection_id": collection_id,
                "user_id": user_id
            })
            # print(result.fetchall())

            return [row[0] for row in result.fetchall()]
        except Exception as e:
            print(f"Error getting IDs for uploaded file: {e}")
            return None       


    def get_all_files(self, collection_id: str) -> Optional[List[str]]:
        try:
            # Execute raw SQL directly since this table is not in our standard models
            sql = text("""
                SELECT DISTINCT cmetadata->>'source' as source
                FROM langchain_pg_embedding
                WHERE collection_id = :collection_id
            """ \
            )
            result = self.session.execute(sql, {
                "collection_id": collection_id
            })

            return [row[0] for row in result.fetchall()]
        except Exception as e:
            print(f"Error getting all files: {e}")
            return []



    def create_model(
        self,
        provider_name: ModelProvider, 
        model_id:str, model_name:str, 
        description:Optional[str]=None, 
        context_window: Optional[int] = None
    ):
        try:
            model = Model(
                provider_name=provider_name,
                model_id=model_id,
                model_name=model_name,
                description=description,
                context_window=context_window
            )
            
            self.session.add(model)
            self.session.commit()
            self.session.refresh(model)
            
            return model     
        except Exception as e:
            self.session.rollback()
            print(f"Error creating model: {e}")
            return None
        
    def get_model_by_provider_and_id(self, provider_name: ModelProvider, model_id: str) -> Optional[Model]:
        return self.session.query(Model).filter(
            Model.provider_name == provider_name,
            Model.model_id == model_id,
            Model.is_deleted == False
        ).first()
        
    def find_model_by_provider_and_id(self, provider_name: ModelProvider, model_id: str):
        return self.session.query(Model).filter(
            Model.provider_name == provider_name,
            Model.model_id == model_id
        ).first()

    def get_model_by_id(self, model_id: str):
        try:
            model = self.session.query(Model).filter(
                Model.id == model_id, Model.is_deleted == False
            ).first()
            return model
        except Exception as e:
            print(f"Error getting model by ID: {e}")
            return None

    def get_all_models(self):
        try:
            return self.session.query(Model).filter(Model.is_deleted == False).all()
        except Exception as e:
            print(f"Error getting all models: {e}")
            return None

    def update_model(self, model_id: str, updates: Dict[str, Any]):
        try:
            model = self.session.query(Model).filter(Model.id == model_id).first()
            if not model:
                return None
            
            for key, value in updates.items():
                setattr(model, key, value)
            
            self.session.commit()
            self.session.refresh(model)
            return model
        except Exception as e:
            print(f"Error updating model: {e}")
            return None

    def undelete_model(
        self,
        model_id: str,
        updates: Dict[str, Any],
    ) -> Optional[Dict[str, Any]]:
        try:
            # ignoring the is_deleted flag
            model = self.session.query(Model).filter(Model.id == model_id).first()
            
            if not model:
                return None

            for key, value in updates.items():
                setattr(model, key, value)
            
            self.session.commit()
            self.session.refresh(model)
            
            return model
        except Exception as e:
            self.session.rollback()
            print(f"Error in undelete_and_update_model: {e}")
            return None
        
    def set_active_model(self, model_id: str):
        try:
            self.session.query(Model).filter(Model.id != model_id).update({"is_active": False})
            
            target_model = self.session.query(Model).filter(Model.id == model_id).first()
            
            if not target_model:
                self.session.rollback() 
                return None

            target_model.is_active = True
            self.session.commit()
            
            return target_model
            
        except Exception as e:
            self.session.rollback()
            print(f"Error setting active AI model: {e}")
            return None
  

    
    def count_models(self) -> int:
        return self.session.query(Model).filter(Model.is_deleted == False).count()

    def soft_delete_model(self, model_id: str):
        if self.count_models() <= 1:
            print("Deletion blocked: Cannot delete the last active model.")
            return False 

        model = self.get_model_by_id(model_id)
        if not model:
            return False

        model.is_deleted = True
        self.session.commit()
        return True

    def get_active_model(self):
        try:
            active_model = self.session.query(Model).filter(
                Model.is_active == True,
                Model.is_deleted == False
            ).first()

            if active_model:
                return active_model
            return None
        except Exception as e:
            print(f"Error getting active model: {e}")
            return None

    def store_message(self, user_id: UUID, content: str, type):
        try:
            # Basic validations
            user = self.get_user_by_id(user_id)
            if not user:
                raise Exception("User not found")

            if content is None or (isinstance(content, str) and content.strip() == ""):
                raise Exception("Message content cannot be empty")

            # Normalize/validate message type
            msg_type = type
            if isinstance(msg_type, str):
                try:
                    msg_type = MessageType(msg_type)
                except Exception:
                    raise Exception("Invalid message type")

            if msg_type not in [MessageType.human, MessageType.ai]:
                raise Exception("Unsupported message type")

            message = Message(user_id=user_id, content=str(content), type=msg_type)
            self.session.add(message)
            self.session.commit()
            self.session.refresh(message)
            return message
        except Exception as e:
            try:
                self.session.rollback()
            except Exception:
                pass
            print(f"Error storing message: {e}")
            return None

    def delete_message(self, user_id: UUID):
        try:
            deleted = self.session.query(Message).filter(
                Message.user_id == user_id
            ).delete(synchronize_session=False)

            self.session.commit()
            return deleted
        except Exception as e:
            try:
                self.session.rollback()
            except Exception:
                pass
            print(f"Error deleting message(s): {e}")
            return 0
        
    def get_all_user_messages(self, user_id: UUID):
        try:
            return self.session.query(Message).filter(Message.user_id==user_id).order_by(Message.created_at.asc()).all()
        except Exception as e:
            print(f"Error fetching user messages: {e}")
            return []