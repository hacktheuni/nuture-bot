from langgraph.graph import add_messages
from langchain_core.messages import AnyMessage
from typing import Annotated, TypedDict, Union
from langchain_google_genai import ChatGoogleGenerativeAI

from sqlalchemy import literal

class ChatState(TypedDict):
    user_id: str
    messages: Annotated[list[AnyMessage], add_messages]
    llm: Union[ChatGoogleGenerativeAI]
    context_window: int | None
