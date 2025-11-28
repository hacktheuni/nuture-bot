from sqlalchemy import Column, String, Boolean, DateTime, func, ForeignKey, Enum, Integer, Text
from sqlalchemy.dialects.postgresql import UUID
from sqlalchemy.orm import declarative_base, relationship

import uuid, enum

Base = declarative_base()

class UserRole(enum.Enum):
    """User role enumeration"""
    user = "user"
    admin = "admin"

class AuthenticationProvider(enum.Enum):
    """Auth Provider enumeration"""
    email = "email"
    google = "google"
    github = "github"
    
class MemoryType(enum.Enum):
    """MemoryType type enumeration"""
    onboarding = "onboarding"
    ai = "ai"

class OTPPurpose(enum.Enum):
    """OTP purpose enumeration"""
    verification = "verification"
    password_reset = "password_reset"

class QuestionType(enum.Enum):
    """QuestionType type enumeration"""
    text = "text"
    mcq = "mcq"
    multiple_choice = "multiple_choice"

class MessageType(enum.Enum):
    """Chat Message type"""
    human = "human"
    ai = "ai"

class ModelProvider(enum.Enum):
    """Model provider enumeration"""
    google_genai = "google_genai"
    openai = "openai"
    anthropic = "anthropic"
    gemini = "gemini"
    
class User(Base):
    __tablename__ = "users"

    id = Column(UUID(as_uuid=True), primary_key=True, default=uuid.uuid4, index=True)
    first_name = Column(String(255), nullable=True)
    last_name = Column(String(255), nullable=True)
    email = Column(String(255), nullable=False, unique=True, index=True)
    role = Column(Enum(UserRole), nullable=False, default=UserRole.user)
    is_active = Column(Boolean, nullable=False, default=True)
    is_verified = Column(Boolean, nullable=False, default=False, index=True)
    is_onboarded = Column(Boolean, nullable=False, default=False)
    created_at = Column(DateTime(timezone=True), nullable=False, server_default=func.now())


class Authentication(Base):
    __tablename__ = "authentications"

    id = Column(UUID(as_uuid=True), primary_key=True, default=uuid.uuid4, index=True)
    user_id = Column(UUID(as_uuid=True), ForeignKey("users.id"), nullable=False, index=True)
    provider = Column(Enum(AuthenticationProvider), nullable=False, index=True)
    provider_user_id = Column(String(255), nullable=True, index=True)
    hashed_password = Column(String(255), nullable=True)
    created_at = Column(DateTime(timezone=True), nullable=False, server_default=func.now())


class Memory(Base):
    __tablename__ = "memories"

    id = Column(UUID(as_uuid=True), primary_key=True, default=uuid.uuid4, index=True)
    user_id = Column(UUID(as_uuid=True), ForeignKey("users.id"), nullable=False, index=True)
    key = Column(String(255), nullable=False, index=True)
    value = Column(Text, nullable=False)
    type = Column(Enum(MemoryType), nullable=False)
    is_deleted = Column(Boolean, nullable=False, default=False, index=True)
    created_at = Column(DateTime(timezone=True), nullable=False, server_default=func.now())
    updated_at = Column(DateTime(timezone=True), nullable=False, server_default=func.now(), onupdate=func.now())


class OnboardingQuestion(Base):
    __tablename__ = "onboarding_questions"

    id = Column(UUID(as_uuid=True), primary_key=True, default=uuid.uuid4, index=True)
    question_text = Column(Text, nullable=False, unique=True)
    question_type = Column(Enum(QuestionType), nullable=False, default=QuestionType.text)
    question_order = Column(Integer, nullable=False, default=0)
    is_active = Column(Boolean, nullable=False, default=True)
    created_at = Column(DateTime(timezone=True), nullable=False, server_default=func.now())
    updated_at = Column(DateTime(timezone=True), nullable=False, server_default=func.now(), onupdate=func.now())

    # Relationship to the available choices for this question.
    choices = relationship("QuestionChoice", back_populates="question", cascade="all, delete-orphan")
    

class QuestionChoice(Base):
    __tablename__ = "question_choices"

    id = Column(UUID(as_uuid=True), primary_key=True, default=uuid.uuid4)
    question_id = Column(UUID(as_uuid=True), ForeignKey("onboarding_questions.id", ondelete="CASCADE"), nullable=False, index=True)
    choice_text = Column(String, nullable=False)

    # Relationship back to the question.
    question = relationship("OnboardingQuestion", back_populates="choices")

class OnboardingAnswers(Base):
    __tablename__ = "onboarding_answers"

    id = Column(UUID(as_uuid=True), primary_key=True, default=uuid.uuid4, index=True)
    user_id = Column(UUID(as_uuid=True), ForeignKey("users.id"), nullable=False, index=True)
    question_id = Column(UUID(as_uuid=True), ForeignKey("onboarding_questions.id"), nullable=False, index=True)
    answer = Column(Text, nullable=False)
    created_at = Column(DateTime(timezone=True), nullable=False, server_default=func.now())

class OTPVerification(Base):
    __tablename__ = "otp_verifications"

    id = Column(UUID(as_uuid=True), primary_key=True, default=uuid.uuid4)
    user_id = Column(UUID(as_uuid=True), ForeignKey("users.id", ondelete="CASCADE"), nullable=False)
    code = Column(String(255), nullable=False)
    purpose = Column(Enum(OTPPurpose), nullable=False, default=OTPPurpose.verification)
    created_at = Column(DateTime(timezone=True), nullable=False, server_default=func.now())
    expires_at = Column(DateTime(timezone=True), nullable=False)
    
    
class RefreshToken(Base):
    __tablename__ = "refresh_tokens"

    id = Column(UUID(as_uuid=True), primary_key=True, default=uuid.uuid4)
    user_id = Column(UUID(as_uuid=True), ForeignKey("users.id", ondelete="CASCADE"), nullable=False, index=True)
    token = Column(String, nullable=False, unique=True, index=True)
    revoked = Column(Boolean, nullable=False, default=False)
    created_at = Column(DateTime(timezone=True), nullable=False, server_default=func.now())
    expires_at = Column(DateTime(timezone=True), nullable=False)

class Model(Base):
    __tablename__ = "models"

    id = Column(UUID(as_uuid=True), primary_key=True, default=uuid.uuid4, index=True)
    provider_name = Column(Enum(ModelProvider), nullable=False)
    model_id = Column(String, nullable=False,index=True)
    model_name = Column(String(255), nullable=False)
    description = Column(String, nullable=True)
    is_active = Column(Boolean, nullable=False, default=False)
    context_window = Column(Integer, nullable=True)
    created_at = Column(DateTime(timezone=True), nullable=False, server_default=func.now())
    updated_at = Column(DateTime(timezone=True), nullable=False, server_default=func.now(), onupdate=func.now())
    is_deleted = Column(Boolean, nullable=False, default=False, index=True)

    
class Message(Base):
    __tablename__ = "messages"

    id = Column(UUID(as_uuid=True), primary_key=True, default=uuid.uuid4, index=True)
    user_id = Column(UUID(as_uuid=True), ForeignKey("users.id"), nullable=False, index=True)
    content = Column(Text, nullable=False)
    type = Column(Enum(MessageType), nullable=False, index=True)
    created_at = Column(DateTime(timezone=True), nullable=False, server_default=func.now())
    updated_at = Column(DateTime(timezone=True), nullable=False, server_default=func.now(), onupdate=func.now())
    is_deleted = Column(Boolean, nullable=False, default=False, index=True)
    

 