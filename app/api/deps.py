from fastapi import Depends, HTTPException, Security, status, Cookie
from typing import Optional
from sqlalchemy.orm import Session
from uuid import UUID

from app.services.crud import DBService 
from app.core.db import SessionLocal  
from app.core.config import settings
from app.utils.auth import verify_token

def get_database_service_session():
    session = SessionLocal()
    try:
        yield session
    finally:
        session.close()

def get_database_service(session: Session = Depends(get_database_service_session)) -> DBService:
    """Get database service with reused session"""
    return DBService(session)

def get_current_user(
    access_token: str = Cookie(None),
    db: DBService = Depends(get_database_service)
):
    """Get current authenticated user from cookie token"""
    if not access_token:
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED, 
            detail="Access token is required"
        )
    
    # Verify token
    payload = verify_token(access_token)
    
    if not payload:
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED, 
            detail="Invalid or expired token"
        )
    
    # Get user from database
    user_id = UUID(payload.get("sub"))
    user = db.get_user_by_id(user_id)
    
    if not user:
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED, 
            detail="User not found"
        )
    
    if not user.is_active:
        raise HTTPException(
            status_code=status.HTTP_403_FORBIDDEN, 
            detail="Account is deactivated"
        )
    
    return user

def require_admin(
    current_user = Depends(get_current_user)
):
    """Require admin role for access"""
    from app.models.database_models import UserRole
    
    if current_user.role != UserRole.admin:
        raise HTTPException(
            status_code=status.HTTP_403_FORBIDDEN,
            detail="Admin privileges required"
        )
    
    return current_user

