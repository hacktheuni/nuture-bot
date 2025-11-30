from uuid import UUID
from datetime import datetime
from pydantic import BaseModel, Field
from typing import Optional, List, Union
from app.models.database_models import QuestionType


class QuestionChoiceSchema(BaseModel):
    id: Optional[UUID] = None
    choice_text: str

class QuestionChoiceResponse(BaseModel):
    id: UUID
    choice_text: str 

class OnboardingQuestionCreate(BaseModel):
    question_text: str = Field(..., min_length=1)
    question_type: QuestionType
    question_order: Optional[int] = None
    choices: Optional[List[QuestionChoiceSchema]] = None
    
class OnboardingQuestionUpdate(BaseModel):
    question_text: Optional[str] = Field(None, min_length=1)
    question_type: Optional[QuestionType] = None
    choices: Optional[List[QuestionChoiceSchema]] = None
    remove_choice_ids: Optional[List[UUID]] = None  

class ReorderRequest(BaseModel):
    ordered_ids: List[UUID]
    
class OnboardingAnswer(BaseModel):
    question_id: UUID
    answer: Union[str, UUID, List[UUID]]

class OnboardingAnswerSubmission(BaseModel):
    answers: List[OnboardingAnswer] = Field(..., min_items=0)
    
    

