from fastapi import APIRouter, Depends, File, Form, UploadFile, Security, HTTPException, status
from fastapi.responses import JSONResponse
from langchain_core.messages import HumanMessage
from langchain_core.documents import Document
from langchain_text_splitters import RecursiveCharacterTextSplitter
from app.utils.loader import load_file
from app.utils.agent import get_vector_store
from app.agent_core.graph import build_graph
from app.agent_core.chat_state import ChatState
import os, json
import asyncio
from sqlalchemy.exc import OperationalError, DisconnectionError
from app.services.crud import DBService
from app.schemas.agent import ChatRequest
from app.api.deps import get_database_service
from app.core.db import SessionLocal
from app.services.agent_checkpointer import clear_thread_checkpoints
from app.models.database_models import User, ModelProvider, MessageType
from app.api.deps import require_admin, get_current_user
from app.utils.model import get_model

router = APIRouter(prefix="/chat", tags=["Chat"])

def get_text_from_message(message):
    """Extract plain text content from an LLM message, no matter the format."""
    if isinstance(message, str):
        return message.strip()

    elif isinstance(message, list):
        text_parts = []
        for part in message:
            if isinstance(part, dict) and part.get("type") == "text":
                if '\"role\": \"assistant\"' in part.get("text"):
                    text = json.loads(part.get("text"))
                    text_parts.append(text.get("content", ""))
                else:
                    text_parts.append(part.get("text", ""))
                
        return "\n".join(text_parts).strip()

    return str(message.content)

@router.post("/upload")
async def upload_file(file: UploadFile = File(...), admin_user: User = Depends(require_admin)):
    allowed_file_types = ["text/plain"]
    if file.content_type not in allowed_file_types:
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail="Invalid file type. " + file.content_type + " is not allowed. Please upload a XLSX or TXT file."
        )
    
    temp_file = f"/tmp/{file.filename}"
    with open(temp_file, "wb") as f:
        f.write(await file.read())

    vector_store = get_vector_store("documents")

    docs = load_file(temp_file)

    # Update metadata to use original filename instead of temp path
    for doc in docs:
        doc.metadata["source"] = file.filename

    splitter = RecursiveCharacterTextSplitter(
        chunk_size=1000,
        chunk_overlap=200,
    )
    docs = splitter.split_documents(docs)

    vector_store.add_documents(docs)

    os.remove(temp_file)
    return {
            "mesg":"File uploaded successfully"
        }

@router.post("/query")
async def query(
        request: ChatRequest,
        db: DBService = Depends(get_database_service),
        user_data: User = Depends(get_current_user)
    ):
    
    user_id= user_data.id
    
    if not user_id:
            raise HTTPException(status_code=401, detail="Invalid session token.")
    
    try:

        model = db.get_active_model()
        llm = get_model(model_name=model.model_id, provider=ModelProvider(model.provider_name))

        graph = build_graph()
        
        config = {"configurable": {"thread_id": user_id}}
        state = ChatState(user_id=user_id, messages=[HumanMessage(content=request.message)], llm=llm, context_window=model.context_window)
        
        # Store human message
        try:
            db.store_message(user_id=user_id, content=request.message, type=MessageType.human)
        except Exception:
            pass

        response = await graph.ainvoke(state, config=config)
        
        # Extract the final AI response from the messages
        final_messages = response["messages"]
        ai_response = None

        # Find the last AI message that's not a tool call
        for msg in reversed(final_messages):
            if msg.type == "ai":
                if not hasattr(msg, 'tool_calls') or not msg.tool_calls:
                    ai_response = msg.content
                    break
        
        if ai_response is None:
            raise HTTPException(
                status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
                detail="Failed to generate AI message"
            )
        
        ai_response = get_text_from_message(ai_response)
        print(ai_response)
        # Store AI message
        try:
            db.store_message(user_id=user_id, content=ai_response, type=MessageType.ai)
        except Exception:
            pass

        vector_store = get_vector_store("chats")
        vector_store.add_documents([Document(page_content=f"Human: {request.message}\nAI: {ai_response}", metadata={"source": "rag", "user_id": str(user_id)})])
        
        return {
                "message": "Chat response generated successfully",
                "query": request.message,
                "ai_response": ai_response
            }
    
    except (OperationalError, DisconnectionError) as e:
        print(f"Database connection error in chat endpoint: {e}")
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail="Database connection error. Please try again."
        )
    except Exception as e:
        print(f"Unexpected error in chat endpoint: {e}")
        msg = str(e).lower()
        if "exceeds context window" in msg:
            raise HTTPException(
                status_code=status.HTTP_400_BAD_REQUEST,
                detail=str(e)
            )
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail="An unexpected error occurred. Please try again."
        )

@router.get("/list")
async def list_all_files(db: DBService = Depends(get_database_service)):
    vector_store = get_vector_store("documents")
    with SessionLocal() as session:
        collection = vector_store.get_collection(session=session)
        if collection is None:
            raise HTTPException(
                status_code=status.HTTP_404_NOT_FOUND,  
                detail="Collection not found"
            )
    files = db.get_all_files(collection.uuid)
    return {
            "message":"Files retrieved successfully",
            "data":{"files": files}
        }

@router.delete("/delete")
async def delete(file_name: str, db: DBService = Depends(get_database_service)):

    vector_store = get_vector_store("documents")
    with SessionLocal() as session:
        collection = vector_store.get_collection(session=session)
        if collection is None:
            raise HTTPException(
                status_code=status.HTTP_404_NOT_FOUND,
                detail="Collection not found"
            )
    ids = db.get_ids_for_uploaded_file(collection.uuid, file_name)
    if ids is None:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail="File not found"
        )
    vector_store.delete(ids)
    return {
            "message":"Files deleted successfully"
    }


@router.delete("/clear_chat_history")
async def clear_chat_history(user_data: User = Depends(get_current_user), db: DBService = Depends(get_database_service)):
    user_id= user_data.id
    
    if not user_id:
            raise HTTPException(status_code=401, detail="Invalid session token.")
    
    vector_store = get_vector_store("chats")
    with SessionLocal() as session:
        collection = vector_store.get_collection(session=session)
        if collection is None:
            raise HTTPException(
                status_code=status.HTTP_404_NOT_FOUND,
                detail="Collection not found"
            )
        
    ids_to_delete = db.get_ids_for_chat_history(collection.uuid, str(user_id))
    
    if ids_to_delete:
        vector_store.delete(ids_to_delete)
    
    
    try:
        clear_thread_checkpoints(str(user_id))
        messages_deleted = db.delete_message(user_id=user_id)
    except Exception:
        pass

    
    return {
            "message":"Chat history cleared successfully"
        }