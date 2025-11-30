from fastapi import APIRouter, Depends, HTTPException, status
from uuid import UUID
from typing import List, Dict, Any
import json

from app.api.deps import get_database_service, require_admin, get_current_user
from app.models.database_models import OnboardingQuestion, User, MemoryType
from app.schemas.onboarding import (
    OnboardingQuestionCreate, 
    OnboardingQuestionUpdate,
    ReorderRequest,
    OnboardingAnswerSubmission
)
from app.services.crud import DBService


router = APIRouter(prefix="/onboarding", tags=["Onboarding"])

@router.post("/question/create")
def create_question(
    request: OnboardingQuestionCreate, 
    admin: User = Depends(require_admin),
    db: DBService = Depends(get_database_service)
):
    """Create a new onboarding question (Admin only)"""
    try:
        # Check for duplicate question text
        existing_question = db.get_question_by_text(request.question_text)
        if existing_question:
            raise HTTPException(
                status_code=status.HTTP_400_BAD_REQUEST, 
                detail="A question with this text already exists"
            )
        
        # Validate choices for MCQ
        if request.question_type.value == "mcq":
            if not request.choices or len(request.choices) < 2:
                raise HTTPException(
                    status_code=status.HTTP_400_BAD_REQUEST,
                    detail="MCQ questions must have at least 2 choices"
                )
        elif request.choices:
            raise HTTPException(
                status_code=status.HTTP_400_BAD_REQUEST,
                detail="Only MCQ questions can have choices"
            )
        
        # Create the question
        new_question = db.create_onboarding_question(
            request.question_text,
            request.question_type,
            request.question_order,
            [choice.choice_text for choice in request.choices] if request.choices else None
        )
        
        return {
            "message": "Question created successfully",
            "data": new_question
        }
    except HTTPException:
        raise
    except Exception as e:
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail=f"Failed to create question: {str(e)}"
        )


@router.post("/question/{question_id}/update")
def update_question(
    question_id: str,
    request: OnboardingQuestionUpdate,
    admin: User = Depends(require_admin),
    db: DBService = Depends(get_database_service)
):
    """Update an existing onboarding question (Admin only)"""
    try:
        question_uuid = UUID(question_id)
        updates = request.dict(exclude_unset=True)
        
        updated_question = db.update_onboarding_question(question_uuid, updates)
        
        if not updated_question:
            raise HTTPException(
                status_code=status.HTTP_404_NOT_FOUND,
                detail="Question not found"
            )
        
        return {
            "message": "Question updated successfully",
            "data": updated_question
        }
    except ValueError:
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail="Invalid question ID format"
        )
    except HTTPException:
        raise
    except Exception as e:
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail=f"Failed to update question: {str(e)}"
        )


@router.delete("/question/{question_id}")
def delete_question(
    question_id: str,
    admin: User = Depends(require_admin),
    db: DBService = Depends(get_database_service)
):
    """Delete an onboarding question (Admin only)"""
    try:
        question_uuid = UUID(question_id)
        deleted = db.delete_question_by_id(question_uuid)
        
        if not deleted:
            raise HTTPException(
                status_code=status.HTTP_404_NOT_FOUND,
                detail="Question not found"
            )
        
        return {
            "message": "Question deleted successfully"
        }
    except ValueError:
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail="Invalid question ID format"
        )
    except HTTPException:
        raise
    except Exception as e:
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail=f"Failed to delete question: {str(e)}"
        )


@router.get("/questions/all")
def get_all_questions(
    admin: User = Depends(require_admin),
    db: DBService = Depends(get_database_service)
):
    """Get all onboarding questions including inactive ones (Admin only)"""
    try:
        # This should be implemented in CRUD
        questions = db.get_all_questions()
        return {
            "data": questions
        }
    except Exception as e:
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail=f"Failed to get questions: {str(e)}"
        )


@router.post("/questions/reorder")
def reorder_questions(
    request: ReorderRequest,
    admin: User = Depends(require_admin),
    db: DBService = Depends(get_database_service)
):
    """Reorder onboarding questions (Admin only)"""
    try:
        success = db.reorder_questions(request.ordered_ids)
        if not success:
            raise HTTPException(
                status_code=status.HTTP_400_BAD_REQUEST,
                detail="Failed to reorder questions"
            )
        
        return {
            "message": "Questions reordered successfully"
        }
    except HTTPException:
        raise
    except Exception as e:
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail=f"Failed to reorder questions: {str(e)}"
        )


@router.post("/submit-answers")
def submit_answers(
    request: OnboardingAnswerSubmission,
    current_user: User = Depends(get_current_user),
    db: DBService = Depends(get_database_service)
):
    """Submit onboarding answers (User only)"""
    try:
        # Save answers to memory
        result = db.save_onboarding_answers(current_user.id, request.answers)
        
        # Check if there were any errors
        if result.get("errors"):
            raise HTTPException(
                status_code=status.HTTP_400_BAD_REQUEST,
                detail=f"Failed to save some answers: {result['errors']}"
            )
        
        # Check if any answers were saved
        if not result.get("saved"):
            raise HTTPException(
                status_code=status.HTTP_400_BAD_REQUEST,
                detail="No answers were saved"
            )
        
        
        return {
            "message": "Onboarding answers submitted successfully",
            "saved_count": len(result.get("saved", []))
        }
    except HTTPException:
        raise
    except Exception as e:
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail=f"Failed to submit answers: {str(e)}"
        )

@router.get('/get_onbarding_questions_answers')
def get_onbaording_questions_answers(
    current_user: User = Depends(get_current_user),
    db: DBService = Depends(get_database_service)
):
    try:
        data = db.get_user_onboarding_answers(current_user.id)
        return {"data": data}
    except Exception as e:
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail=f"Failed to get onboarding answers: {str(e)}"
        )