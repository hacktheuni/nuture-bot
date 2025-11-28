from fastapi import APIRouter, Depends, HTTPException, Request, status, Cookie
from app.api.deps import get_database_service, get_current_user
from app.models.database_models import OnboardingQuestion, OnboardingAnswers, User
from app.schemas.auth import UserUpdateProfileRequest, ChangePasswordRequest
from app.services.crud import DBService
from uuid import UUID
from app.utils.auth import oauth



router = APIRouter(prefix="/user", tags=["User"])

@router.get("/me")
def user_profile(current_user: User = Depends(get_current_user)):
    return {
        "data": current_user
    }


@router.put("/profile/update")
def user_profile_update(request: UserUpdateProfileRequest, current_user: User = Depends(get_current_user), db: DBService = Depends(get_database_service)):

    try:
        user_data = db.update_user_by_id(current_user.id, request.first_name, request.last_name)

        if not user_data:
            raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail="User not found")

        return {
            "message": "Profile updated successfully",
            "data": user_data
        }
    except HTTPException:
        raise
    except Exception as e:
        raise HTTPException(status_code=status.HTTP_500_INTERNAL_SERVER_ERROR, detail=f"Failed to update profile: {str(e)}")


@router.delete("/profile/delete")
def user_profile_delete(current_user: User = Depends(get_current_user), db: DBService = Depends(get_database_service)):
    try:
        user_data = db.delete_user_by_id(current_user.id)

        return {
            "message": "Account deleted successfully"
        }
    except HTTPException as e:
        raise e
    except Exception as e:
        raise HTTPException(status_code=status.HTTP_500_INTERNAL_SERVER_ERROR, detail=f"Failed to delete account: {str(e)}")


@router.delete("/unlink/{provider}")
def unlink_account(provider: str, current_user: User = Depends(get_current_user), db: DBService = Depends(get_database_service)):
    """Unlink OAuth provider from user account"""
    if provider not in ['google', 'github']:
        raise HTTPException(status_code=status.HTTP_400_BAD_REQUEST, detail="Unsupported provider")
    
    try:
        unlinked = db.unlink_oauth_provider_from_user(current_user.id, provider)
        
        return {
            "message": f"{provider.capitalize()} account unlinked successfully"
        }
    except HTTPException:
        raise
    except Exception as e:
        error_message = str(e).lower()
        
        # Handle specific error cases
        if "not linked" in error_message:
            raise HTTPException(
                status_code=status.HTTP_400_BAD_REQUEST, 
                detail=f"{provider.capitalize()} account is not linked to your account"
            )
        elif "set up an email password first" in error_message or "setup" in error_message:
            raise HTTPException(
                status_code=status.HTTP_400_BAD_REQUEST,
                detail="Cannot unlink OAuth provider. Please set up an email password first before unlinking OAuth providers."
            )
        elif "cannot unlink" in error_message or "last remaining" in error_message:
            raise HTTPException(
                status_code=status.HTTP_400_BAD_REQUEST,
                detail="Cannot unlink the last remaining authentication method. Please add another authentication method first."
            )
        elif "unsupported oauth provider" in error_message:
            raise HTTPException(
                status_code=status.HTTP_400_BAD_REQUEST,
                detail="Unsupported OAuth provider"
            )
        else:
            # Generic error
            raise HTTPException(
                status_code=status.HTTP_500_INTERNAL_SERVER_ERROR, 
                detail=f"Failed to unlink account: {str(e)}"
            )


@router.get("/onboarding-questions")
def get_onboarding_questions(current_user: User = Depends(get_current_user), db: DBService = Depends(get_database_service)):
    try:
        questions = db.get_active_onboarding_questions()
        return {
            "data": questions
        }
    except Exception as e:
        raise HTTPException(status_code=status.HTTP_500_INTERNAL_SERVER_ERROR, detail=f"Failed to get onboarding questions: {str(e)}")

   
@router.post("/change-password")
def change_password(request: ChangePasswordRequest, current_user: User = Depends(get_current_user), db: DBService = Depends(get_database_service)):
    try:
        pass_changed = db.change_user_password(current_user.id, request.current_password, request.new_password)
        
        return {
            "message": "Password changed successfully"
        }
    except HTTPException as e:
        raise e
    except Exception as e:
        error_message = str(e).lower()
        if "email authentication not found" in error_message:
            raise HTTPException(status_code=status.HTTP_400_BAD_REQUEST, detail="Email authentication not found. Cannot change password for this account.")
        elif "incorrect" in error_message:
            raise HTTPException(status_code=status.HTTP_401_UNAUTHORIZED, detail="Current password is incorrect")
        raise HTTPException(status_code=status.HTTP_500_INTERNAL_SERVER_ERROR, detail=f"Failed to change password: {str(e)}")

@router.get('/pending_onbarding_answer')
def pending_onbarding_answer(current_user: User = Depends(get_current_user), db: DBService = Depends(get_database_service)):

    if current_user:
        user_id = current_user.id
    try:
        total_active_questions = db.session.query(OnboardingQuestion).filter(OnboardingQuestion.is_active == True).count()

        # Count distinct answered active questions for the user
        answered_active_questions = (
            db.session.query(OnboardingAnswers.question_id)
            .join(OnboardingQuestion, OnboardingQuestion.id == OnboardingAnswers.question_id)
            .filter(
                OnboardingAnswers.user_id == user_id,
                OnboardingQuestion.is_active == True,
            )
            .distinct()
            .count()
        )

        is_complete = answered_active_questions >= total_active_questions

        return {
            "data": is_complete
        }
    except Exception as e:
        raise HTTPException(status_code=status.HTTP_500_INTERNAL_SERVER_ERROR, detail=f"Failed to check onboarding answers: {str(e)}")
    
@router.get("/get-all-messages")
def get_all_messages(current_user: User = Depends(get_current_user), db: DBService = Depends(get_database_service)):
    try:
        user_id = current_user.id
        messages = db.get_all_user_messages(user_id)
        return [
                {
                    "type": mesg.type,
                    "content": mesg.content,
                    "created_at": mesg.created_at
                } for mesg in messages
            ]
    except Exception as e:
        raise HTTPException(status_code=status.HTTP_500_INTERNAL_SERVER_ERROR, detail=f"Failed to get messages: {str(e)}")