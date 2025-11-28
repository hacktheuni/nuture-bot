from pydantic import BaseModel
from typing import Optional
from datetime import datetime
from uuid import UUID
from app.models.database_models import ModelProvider

    
class ModelCreateRequest(BaseModel):
    provider_name: ModelProvider
    model_id: str
    model_name: str
    description: Optional[str] = None
    context_window: Optional[int] = None
    

class ModelUpdateRequest(BaseModel):
    provider_name: Optional[ModelProvider] = None
    model_id: Optional[str] = None
    model_name: Optional[str] = None
    description: Optional[str] = None
    context_window: Optional[int] = None