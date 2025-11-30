from fastapi import FastAPI
from fastapi.middleware.cors import CORSMiddleware
from starlette.middleware.sessions import SessionMiddleware

from app.api.v1.auth import router as auth_router 
from app.api.v1.admin import router as admin_router
from app.api.v1.user import router as user_router
from app.api.v1.onboarding import router as onboarding_router
from app.api.v1.agent import router as chatbot_router
from app.api.v1.model import router as model_router
from app.services.agent_checkpointer import lifespan_checkpointer

app = FastAPI(lifespan=lifespan_checkpointer)

app.add_middleware(
    SessionMiddleware, secret_key="7743ec4f8914a4b6b35aaea70e836e5d8db8"
)

app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"]
)

app.include_router(auth_router)
app.include_router(admin_router)
app.include_router(user_router)
app.include_router(onboarding_router)
app.include_router(chatbot_router)
app.include_router(model_router)




