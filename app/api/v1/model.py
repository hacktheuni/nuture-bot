from fastapi import APIRouter, Depends, HTTPException, status
from uuid import UUID

from app.schemas.model import ModelCreateRequest, ModelUpdateRequest
from app.api.deps import get_database_service
from app.services.crud import DBService
from app.api.deps import require_admin

router = APIRouter(prefix="/models", tags=["models"])


@router.get("/all")
async def get_all_avialble_models(
    admin_user: dict = Depends(require_admin),
    db: DBService = Depends(get_database_service)
):
    models = db.get_all_models()
    print("Models",models)
    if not models:
        return {
            "message": "No models found.",
        }
        
    return {
        "message": "Successfully retrieved all models.",
        "data": models,
    }
  
@router.get("/{model_id}")
async def get_model_by_id(

    model_id: UUID, 
    db: DBService = Depends(get_database_service),
    admin_user: dict = Depends(require_admin),
):
    # print("model_id",model_id)
    if not model_id:
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail="Model ID is required."
        )

    model_data = db.get_model_by_id(model_id)
    
    if not model_data:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail=f"Model with ID '{model_id}' not found."
        )
        
    return {
        "message": "Model retrieved successfully.",
        "data": model_data,
    }
    
@router.post("/create")
async def create_new_model(
    request: ModelCreateRequest,
    db: DBService = Depends(get_database_service),
    admin_user: dict = Depends(require_admin)
):
    # 1. Check if a model with this provider and ID already exists also check soft deleted
    existing_model = db.find_model_by_provider_and_id(
        request.provider_name, request.model_id
    )
        
    if existing_model:
        if existing_model.is_deleted:
            updates = request.dict()
            updates["is_deleted"] = False # Restore the model
            restored_updated_model_data = db.undelete_model(str(existing_model.id), updates)
            return {
                "message": "Model restored successfully.",
                "data": restored_updated_model_data,
            }
        else:
            # 3. If it exists and is NOT deleted, it's a true conflict.
            raise HTTPException(
                status_code=status.HTTP_409_CONFLICT,
                detail=f"A model with provider '{request.provider_name.value}' and model ID '{request.model_id}' already exists."
            )
            
    new_model_data = db.create_model(
        provider_name=request.provider_name,
        model_id=request.model_id,
        model_name=request.model_name,
        description=request.description,
        context_window=request.context_window
    )

    if not new_model_data:
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail="Failed to create the model for an unknown reason."
        )

    return {
        "message": "Model created successfully.",
        "data": new_model_data,
    }

@router.patch("/{model_id}/update")
async def update_model_details(
    model_id: UUID,
    request: ModelUpdateRequest,
    db: DBService = Depends(get_database_service),
    admin_user: dict = Depends(require_admin)
):
    # 1. First, check if the model exists
    existing_model = db.get_model_by_id(str(model_id))
    if not existing_model:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail=f"Model with ID '{model_id}' not found."
        )

    # 2. If it exists, proceed with the update
    updates = request.dict(exclude_unset=True)
    if not updates:
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail="No update data provided."
        )

    updated_model = db.update_model(str(model_id), updates)

    if not updated_model:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail=f"Model with ID '{model_id}' could not be updated."
        )

    return {
        "message": "Model updated successfully.",
        "data": updated_model,
    }


@router.delete("/{model_id}/delete")
async def delete_model(
    model_id: UUID,
    db: DBService = Depends(get_database_service),
    admin_user: dict = Depends(require_admin)
):
    # 1. First, check if the model exists.
    existing_model = db.get_model_by_id(str(model_id))
    if not existing_model:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail=f"Model with ID '{model_id}' not found."
        )

    # 2. If it exists, attempt the soft delete.
    success = db.soft_delete_model(str(model_id))

    if not success:
        # This block now specifically handles the "last model" case.
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail="Cannot delete the last remaining model."
        )

    return  {
        "message": f"Model with ID '{model_id}' has been successfully deleted.",
        "data": None,
    }


@router.patch("/{model_id}/activate")
async def activate_model(
    model_id: UUID,
    db: DBService = Depends(get_database_service),
    admin_user: dict = Depends(require_admin)
):
    existing_model = db.get_model_by_id(str(model_id))
    if not existing_model:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail=f"Model with ID '{model_id}' not found."
        )

    updated_model = db.set_active_model(str(model_id))

    if not updated_model:
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail=f"Failed to set model as active."
        )

    return {
        "message": "Model has been set as active.",
        "data": updated_model,
    }