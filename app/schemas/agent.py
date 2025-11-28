from typing import List, Any, Dict, Optional
from datetime import datetime
from pydantic import BaseModel, Field

class ChatRequest(BaseModel):
    message: str = Field(..., description="The message to chat with")

