from fastapi import APIRouter, Depends, HTTPException, status, Cookie
from uuid import UUID

from app.models.database_models import UserRole, User
from app.schemas.auth import UserRegisterRequest
from app.services.crud import DBService
from app.api.deps import get_database_service, require_admin, get_current_user
from app.utils.auth import hash_password


router = APIRouter(prefix="/admin", tags=["Admin"])

@router.post('/create-admin')
def create_admin(request: UserRegisterRequest, db: DBService = Depends(get_database_service), admin: User = Depends(require_admin)):

    request.email = request.email.lower()

    existing_user = db.get_user_by_email(request.email)

    if existing_user:
        raise HTTPException(status_code=400, detail="Email already registered")
    
    hashed_password = hash_password(request.password)
    try:
        user_data = db.create_user_with_email_auth(
            first_name = request.first_name,
            last_name = request.last_name,
            email = request.email,
            role = UserRole.admin,
            is_verified = True,
            is_onboarded = True,
            hashed_password=hashed_password
        )
        
        return {
            "message": "Admin created successfully",
            "data": user_data
        }
    except Exception as e:
        raise HTTPException(status_code=status.HTTP_500_INTERNAL_SERVER_ERROR, detail=f"Failed to create admin: {str(e)}")


@router.get('/get-admins')
def get_admins(db: DBService = Depends(get_database_service), admin: User = Depends(require_admin)):
    admins = db.get_all_admins()

    return {
        "data": admins
    }


@router.get('/get-users')
def get_users(db: DBService = Depends(get_database_service), admin: User = Depends(require_admin)):
    users = db.get_all_users()

    return {
        "data": users
    }


@router.get('/user/{user_id}/detail')
def get_user_detail(user_id: str, db: DBService = Depends(get_database_service), admin: User = Depends(require_admin)):
    try:
        user_uuid = UUID(user_id)
        user_data = db.get_user_by_id(user_uuid)

        if not user_data:
            raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail="User not found")

        return {
            "data": user_data
        }
    except ValueError:
        raise HTTPException(status_code=status.HTTP_400_BAD_REQUEST, detail="Invalid user ID format")
    except Exception as e:
        raise HTTPException(status_code=status.HTTP_500_INTERNAL_SERVER_ERROR, detail=f"Failed to get user details: {str(e)}")


@router.post('/user/{user_id}/activate')
def activate_user(user_id: str, db: DBService = Depends(get_database_service), admin: User = Depends(require_admin)):
    try:
        user_id = UUID(user_id)
        user = db.activate_user_by_id(user_id)

        if not user:
            raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail="User not found")

        return {
            "message": "User activated successfully",
            "data": user
        }
    except HTTPException:
        raise
    except Exception as e:
        raise HTTPException(status_code=status.HTTP_500_INTERNAL_SERVER_ERROR, detail=f"Failed to activate user: {str(e)}")


@router.post('/user/{user_id}/deactivate')
def deactivate_user(user_id: str, db: DBService = Depends(get_database_service), admin: User = Depends(require_admin)):
    try:
        user_id = UUID(user_id)
        user = db.deactivate_user_by_id(user_id)

        if not user:
            raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail="User not found")

        return {
            "message": "User deactivated successfully",
            "data": user
        }
    except HTTPException:
        raise
    except Exception as e:
        raise HTTPException(status_code=status.HTTP_500_INTERNAL_SERVER_ERROR, detail=f"Failed to deactivate user: {str(e)}")
