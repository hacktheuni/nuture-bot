from fastapi import APIRouter, Request, Depends, HTTPException, Response, status, Cookie
from uuid import UUID
import re

from app.api.deps import get_database_service, get_current_user
from app.models.database_models import User, OTPPurpose
from app.services.crud import DBService
from app.schemas.auth import UserRegisterRequest, LoginResponse, UserLoginRequest, OTPSendRequest, VerifyOTPRequest, ResetPasswordRequest, VerifyResetTokenRequest
from app.utils.auth import oauth, create_access_token, create_refresh_token, hash_password, verify_password, verify_token
from app.utils.otp import generate_otp, send_email_otp


router = APIRouter(prefix="/auth", tags=["auth"])

# Email validation regex
EMAIL_REGEX = re.compile(r'^[a-zA-Z0-9._%+-]+@[a-zA-Z0-9.-]+\.[a-zA-Z]{2,}$')

# Password validation regex - at least 8 chars, 1 uppercase, 1 lowercase, 1 digit
PASSWORD_REGEX = re.compile(r'^(?=.*[a-z])(?=.*[A-Z])(?=.*\d)[a-zA-Z\d@$!%*?&]{8,}$')

def validate_email(email: str) -> str:
    """Validate and normalize email"""
    if not email:
        raise HTTPException(status_code=status.HTTP_400_BAD_REQUEST, detail="Email is required")
    
    email = email.lower().strip()
    
    if not EMAIL_REGEX.match(email):
        raise HTTPException(status_code=status.HTTP_400_BAD_REQUEST, detail="Invalid email format")
    
    return email

def validate_password(password: str) -> str:
    """Validate password strength"""
    if not password:
        raise HTTPException(status_code=status.HTTP_400_BAD_REQUEST, detail="Password is required")
    
    if len(password) < 8:
        raise HTTPException(status_code=status.HTTP_400_BAD_REQUEST, detail="Password must be at least 8 characters long")
    
    if not re.search(r'[a-z]', password):
        raise HTTPException(status_code=status.HTTP_400_BAD_REQUEST, detail="Password must contain at least one lowercase letter")
    
    if not re.search(r'[A-Z]', password):
        raise HTTPException(status_code=status.HTTP_400_BAD_REQUEST, detail="Password must contain at least one uppercase letter")
    
    if not re.search(r'\d', password):
        raise HTTPException(status_code=status.HTTP_400_BAD_REQUEST, detail="Password must contain at least one digit")
    
    return password

def validate_name(name: str, field_name: str = "Name") -> str:
    """Validate name fields"""
    if not name:
        return ""
    
    name = name.strip()
    
    if len(name) > 255:
        raise HTTPException(status_code=status.HTTP_400_BAD_REQUEST, detail=f"{field_name} must be 255 characters or less")
    
    if not re.match(r'^[a-zA-Z\s\-\.]+$', name):
        raise HTTPException(status_code=status.HTTP_400_BAD_REQUEST, detail=f"{field_name} contains invalid characters")
    
    return name


@router.post("/register")
def register(request: UserRegisterRequest, response: Response, db: DBService = Depends(get_database_service)):
    # Validate email
    email = validate_email(request.email)
    
    # Validate password
    password = validate_password(request.password)
    
    # Validate names
    first_name = validate_name(request.first_name or "", "First name") if request.first_name else ""
    last_name = validate_name(request.last_name or "", "Last name") if request.last_name else ""
    
    if not first_name:
        raise HTTPException(status_code=status.HTTP_400_BAD_REQUEST, detail="First name is required")
    
    if not last_name:
        raise HTTPException(status_code=status.HTTP_400_BAD_REQUEST, detail="Last name is required")
    
    # Check if user already exists
    existing_user = db.get_user_by_email(email)
    
    if existing_user:
        raise HTTPException(status_code=status.HTTP_400_BAD_REQUEST, detail="Email already registered")
    
    try:
        # Create user
        hashed_password = hash_password(password)
        user_data = db.create_user_with_email_auth(email, hashed_password, first_name, last_name)
        
        if not user_data:
            raise HTTPException(status_code=status.HTTP_500_INTERNAL_SERVER_ERROR, detail="Failed to create user")
        
        # Issue token immediately
        access_token = create_access_token({"sub": str(user_data.id), "email": user_data.email, "role": str(user_data.role)})
        refresh_token = create_refresh_token()
        
        try:
            db.store_refresh_token(user_data.id, refresh_token)
        except Exception as e:
            raise HTTPException(status_code=status.HTTP_500_INTERNAL_SERVER_ERROR, detail=f"Failed to store refresh token: {str(e)}")
        
        if response:
            response.set_cookie(key="access_token", value=access_token, httponly=True, secure=True, samesite="lax")
            response.set_cookie(key="refresh_token", value=refresh_token, httponly=True, secure=True, samesite="lax")
        
        response_data = LoginResponse(
            access_token=access_token,
            refresh_token=refresh_token
        )
        return {
            "message": "User registered successfully",
            "data": response_data
        }
    except HTTPException:
        raise
    except Exception as e:
        raise HTTPException(status_code=status.HTTP_500_INTERNAL_SERVER_ERROR, detail=f"Registration failed: {str(e)}")


@router.post("/login/email")
def login_with_email(response: Response, request: UserLoginRequest, db: DBService = Depends(get_database_service)):
    # Validate email
    email = validate_email(request.email)
    
    # Validate password
    if not request.password:
        raise HTTPException(status_code=status.HTTP_400_BAD_REQUEST, detail="Password is required")
    
    # Get user
    user_data = db.get_user_by_email(email)
    
    if not user_data:
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Invalid email or password.",
        )
    
    # Check if user is active
    if not user_data.is_active:
        raise HTTPException(
            status_code=status.HTTP_403_FORBIDDEN,
            detail="This account has been deactivated by an administrator."
        )
    
    # Get email authentication
    email_auth = db.get_user_email_auth(email)
    
    if not email_auth:
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Invalid email or password.",
        )
    
    # Verify password
    if not verify_password(request.password, email_auth.hashed_password):
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Invalid email or password."
        )
    
    # Issue tokens
    access_token = create_access_token({"sub": str(user_data.id), "email": user_data.email, "role": str(user_data.role)})
    refresh_token = create_refresh_token()
    
    try:
        db.store_refresh_token(user_data.id, refresh_token)
    except Exception as e:
        raise HTTPException(status_code=status.HTTP_500_INTERNAL_SERVER_ERROR, detail=f"Failed to store refresh token: {str(e)}")
    
    if response:
        response.set_cookie(key="access_token", value=access_token, httponly=True, secure=True, samesite="lax")
        response.set_cookie(key="refresh_token", value=refresh_token, httponly=True, secure=True, samesite="lax")
    
    response_data = LoginResponse(
        access_token=access_token,
        refresh_token=refresh_token
    )
    print(response)
    print("Login successful")
    return {
        "message": "Login successful",
        "data": response_data
    }


@router.get("/login/{provider}")
async def login(request: Request, provider: str):
    """Initiate OAuth login flow"""
    if provider not in ['google', 'github']:
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail="Unsupported provider")
    
    try:
        redirect_uri = f"http://localhost:8000/auth/{provider}/callback"
        
        if provider == "google":
            return await oauth.google.authorize_redirect(request, redirect_uri, state="login")
        elif provider == "github":
            return await oauth.github.authorize_redirect(request, redirect_uri, state="login")
    except Exception as e:
        raise HTTPException(status_code=status.HTTP_500_INTERNAL_SERVER_ERROR, detail=f"OAuth initialization failed: {str(e)}")


@router.get("/{provider}/callback")
async def unified_oauth_callback(
    response: Response,
    request: Request,
    provider: str,
    db: DBService = Depends(get_database_service),
    access_token: str = Cookie(None)
):
    """Handle OAuth callback for both login and linking"""
    if provider not in ['google', 'github']:
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail="Unsupported provider")
    
    try:
        # Get action from state parameter
        state = request.query_params.get("state", "login")
        action = state if state in ["login", "link"] else "login"
        
        # Extract OAuth user information
        if provider == "google":
            token = await oauth.google.authorize_access_token(request)
            user_info = token.get("userinfo")
            if not user_info:
                raise HTTPException(status_code=status.HTTP_400_BAD_REQUEST, detail="Failed to retrieve user information from Google")
            
            provider_user_id = user_info.get("sub")
            email = user_info.get("email")
            first_name = user_info.get("given_name")
            last_name = user_info.get("family_name")
            
        elif provider == "github":
            token = await oauth.github.authorize_access_token(request)
            resp = await oauth.github.get("user", token=token)
            profile = resp.json()
            
            emails_resp = await oauth.github.get("user/emails", token=token)
            emails = emails_resp.json()
            primary_email = next((e["email"] for e in emails if e.get("primary") and e.get("verified")), None)
            
            if not primary_email:
                raise HTTPException(status_code=status.HTTP_400_BAD_REQUEST, detail="No verified primary email found in GitHub account")
            
            profile["email"] = primary_email
            provider_user_id = str(profile.get("id"))
            email = profile.get("email")
            first_name = None
            last_name = None
        else:
            raise HTTPException(status_code=status.HTTP_400_BAD_REQUEST, detail="Provider not supported")
        
        # Validate email and provider_user_id
        if not email:
            raise HTTPException(status_code=status.HTTP_400_BAD_REQUEST, detail="Email not found in OAuth provider")
        
        email = validate_email(email)
        
        if not provider_user_id:
            raise HTTPException(status_code=status.HTTP_400_BAD_REQUEST, detail="Provider user ID not found")
        
        # Handle account linking
        if action == "link":
            payload = verify_token(access_token)
            
            if not access_token or not payload:
                raise HTTPException(status_code=status.HTTP_401_UNAUTHORIZED, detail="Authentication required for linking")
            
            user_id = UUID(payload.get('sub'))
            user = db.get_user_by_id(user_id)
            
            if not user:
                raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail="User not found")
            
            # Check if provider is already linked to this user
            existing_link = db.get_user_oauth_auth(provider, provider_user_id)
            if existing_link:
                raise HTTPException(status_code=status.HTTP_400_BAD_REQUEST, detail=f"{provider.capitalize()} account is already linked to another account")
            
            # Link the provider
            try:
                link = db.link_oauth_provider_to_user(user.id, provider, provider_user_id)
            except Exception as e:
                error_message = str(e).lower()
                if "already linked" in error_message:
                    raise HTTPException(status_code=status.HTTP_400_BAD_REQUEST, detail=str(e))
                raise HTTPException(status_code=status.HTTP_500_INTERNAL_SERVER_ERROR, detail=f"Failed to link account: {str(e)}")
            
            return {"message": f"{provider.capitalize()} account linked successfully"}
        
        # Handle login/registration
        else:
            try:
                user = db.login_or_register_with_oauth(
                    email=email,
                    first_name=first_name or "",
                    last_name=last_name or "",
                    provider=provider,
                    provider_user_id=provider_user_id,
                )
                
                if not user:
                    raise HTTPException(
                        status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
                        detail="Could not process social authentication."
                    )
                
                # Issue tokens
                access_token = create_access_token({"sub": str(user["id"]), "email": user["email"], "role": str(user["role"])})
                refresh_token = create_refresh_token()
                
                try:
                    db.store_refresh_token(user["id"], refresh_token)
                except Exception as e:
                    raise HTTPException(status_code=status.HTTP_500_INTERNAL_SERVER_ERROR, detail=f"Failed to store refresh token: {str(e)}")
                
                if response:
                    response.set_cookie(key="access_token", value=access_token, httponly=True, secure=True, samesite="lax")
                    response.set_cookie(key="refresh_token", value=refresh_token, httponly=True, secure=True, samesite="lax")
                
                response_data = LoginResponse(
                    access_token=access_token,
                    refresh_token=refresh_token
                )
                return {
                    "message": "Authentication successful",
                    "data": response_data
                }
            except HTTPException as e:
                # Re-raise HTTP exceptions
                raise e
            except Exception as e:
                # Handle specific errors from login_or_register_with_oauth
                error_message = str(e).lower()
                
                if "deactivated" in error_message:
                    raise HTTPException(
                        status_code=status.HTTP_403_FORBIDDEN,
                        detail="Your account has been deactivated. Please contact support."
                    )
                elif "already linked" in error_message:
                    raise HTTPException(
                        status_code=status.HTTP_400_BAD_REQUEST,
                        detail=f"This {provider} account is already linked to another user account."
                    )
                elif "user not found" in error_message:
                    raise HTTPException(
                        status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
                        detail="Database inconsistency detected. Please contact support."
                    )
                else:
                    # Generic error handler
                    raise HTTPException(
                        status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
                        detail=f"OAuth authentication failed: {str(e)}"
                    )
    
    except HTTPException:
        raise
    except Exception as e:
        raise HTTPException(status_code=status.HTTP_500_INTERNAL_SERVER_ERROR, detail=f"OAuth callback failed: {str(e)}")


@router.get("/link/{provider}")
async def link_account(request: Request, provider: str, curent_user: User = Depends(get_current_user)):
    """Initiate OAuth account linking flow"""

    if not curent_user:
        raise HTTPException(status_code=status.HTTP_401_UNAUTHORIZED, detail=f"Not Authenticated: {str(e)}")

    try:
        redirect_uri = f"http://localhost:8000/auth/{provider}/callback"
        
        if provider == "google":
            return await oauth.google.authorize_redirect(request, redirect_uri, state="link")
        elif provider == "github":
            return await oauth.github.authorize_redirect(request, redirect_uri, state="link")
    except Exception as e:
        raise HTTPException(status_code=status.HTTP_500_INTERNAL_SERVER_ERROR, detail=f"Failed to initiate linking: {str(e)}")


@router.post("/refresh")
def regenerate_token(response: Response, refresh_token: str = Cookie(None), db: DBService = Depends(get_database_service)):
    """Refresh access token using refresh token"""
    if not refresh_token:
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Refresh token is required"
        )
    
    user_id = None
    if refresh_token:
        user_id = db.use_refresh_token(refresh_token)
    
    if not user_id:
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Invalid or expired refresh token. Please log in again."
        )
    
    try:
        # Issue new tokens
        user_data = db.get_user_by_id(user_id)
        
        if not user_data:
            raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail="User not found")
        
        if not user_data.is_active:
            raise HTTPException(status_code=status.HTTP_403_FORBIDDEN, detail="Account is deactivated")
        
        access_token = create_access_token({"sub": str(user_data.id), "email": user_data.email, "role": str(user_data.role)})
        new_refresh_token = create_refresh_token()
        
        try:
            db.store_refresh_token(user_id, new_refresh_token)
        except Exception as e:
            raise HTTPException(status_code=status.HTTP_500_INTERNAL_SERVER_ERROR, detail=f"Failed to store refresh token: {str(e)}")
        
        if response:
            response.set_cookie(key="access_token", value=access_token, httponly=True, secure=True, samesite="lax")
            response.set_cookie(key="refresh_token", value=new_refresh_token, httponly=True, secure=True, samesite="lax")
        
        response_data = LoginResponse(
            access_token=access_token,
            refresh_token=refresh_token
        )
        return {
            "message": "Access token refreshed successfully",
            "data": response_data
        }
    except HTTPException:
        raise
    except Exception as e:
        raise HTTPException(status_code=status.HTTP_500_INTERNAL_SERVER_ERROR, detail=f"Failed to refresh token: {str(e)}")


@router.post("/logout")
def logout(access_token: str = Cookie(None), response: Response = None, db: DBService = Depends(get_database_service)):
    """Logout user and invalidate refresh tokens"""
    if not response:
        raise HTTPException(status_code=status.HTTP_500_INTERNAL_SERVER_ERROR, detail="Response object not available")
    
    payload = verify_token(access_token)
    
    if not access_token or not payload:
        # Clear cookies even if token is invalid
        response.delete_cookie(key="access_token")
        response.delete_cookie(key="refresh_token")
        return {"message": "Logged out successfully"}
    
    user_id = UUID(payload.get("sub"))
    
    try:
        db.delete_all_refresh_tokens_for_user(user_id)
        
        response.delete_cookie(key="access_token")
        response.delete_cookie(key="refresh_token")
        
        return {"message": "Logged out successfully"}
    except Exception as e:
        # Still clear cookies even if database operation fails
        response.delete_cookie(key="access_token")
        response.delete_cookie(key="refresh_token")
        raise HTTPException(status_code=status.HTTP_500_INTERNAL_SERVER_ERROR, detail=f"Logout failed: {str(e)}")


@router.post("/send_otp")
def send_otp(request: OTPSendRequest, db: DBService = Depends(get_database_service)):
    """Send OTP to user's email"""
    email = validate_email(request.email)
    
    user = db.get_user_by_email(email)
    
    if not user:
        # Don't reveal if user exists or not for security
        return {"message": f"If the email exists, OTP will be sent to {email}"}
    
    try:
        otp = generate_otp()
        
        try:
            db.store_otp(user.id, otp, purpose=OTPPurpose.verification)
        except Exception as e:
            raise HTTPException(status_code=status.HTTP_500_INTERNAL_SERVER_ERROR, detail=f"Failed to store OTP: {str(e)}")
        
        send_email_otp(user.email, otp)
        
        return {"message": f"OTP sent to {email}"}
    except HTTPException:
        raise
    except Exception as e:
        raise HTTPException(status_code=status.HTTP_500_INTERNAL_SERVER_ERROR, detail=f"Failed to send OTP: {str(e)}")


@router.post("/verify_otp")
def verify_otp(request: VerifyOTPRequest, db: DBService = Depends(get_database_service)):
    """Verify OTP and activate user"""
    email = validate_email(request.email)
    
    # Validate OTP format
    if not request.otp or len(request.otp) != 6 or not request.otp.isdigit():
        raise HTTPException(status_code=status.HTTP_400_BAD_REQUEST, detail="Invalid OTP format")
    
    user = db.get_user_by_email(email)
    
    if not user:
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail="User not found")
    
    try:
        otp_verified = db.verify_otp(user.id, request.otp, purpose=OTPPurpose.verification)
        
        return {"message": "OTP verified successfully. Your account has been activated."}
    except HTTPException:
        raise
    except Exception as e:
        raise HTTPException(status_code=status.HTTP_500_INTERNAL_SERVER_ERROR, detail=f"Failed to verify OTP: {str(e)}")


@router.post("/send-reset-otp")
def send_reset_otp(request: ResetPasswordRequest, db: DBService = Depends(get_database_service)):
    """Send password reset OTP to user's email"""
    email = validate_email(request.email)
    
    user = db.get_user_by_email(email)
    
    if not user:
        return {"message": f"If the email exists, password reset OTP will be sent to {email}"}
    
    if not user.is_active:
        raise HTTPException(status_code=status.HTTP_403_FORBIDDEN, detail="Account is deactivated")
    
    try:
        otp = generate_otp()
        
        try:
            db.store_otp(user.id, otp, purpose=OTPPurpose.password_reset)
        except Exception as e:
            raise HTTPException(status_code=status.HTTP_500_INTERNAL_SERVER_ERROR, detail=f"Failed to store password reset OTP: {str(e)}")
        
        send_email_otp(user.email, otp)
        
        return {"message": f"Password reset OTP sent to {email}"}
    except HTTPException:
        raise
    except Exception as e:
        raise HTTPException(status_code=status.HTTP_500_INTERNAL_SERVER_ERROR, detail=f"Failed to send reset OTP: {str(e)}")


@router.post("/reset-password")
def reset_password(request: VerifyResetTokenRequest, db: DBService = Depends(get_database_service)):
    """Reset password using OTP and email"""
    email = validate_email(request.email)
    
    # Validate OTP format
    if not request.otp or len(request.otp) != 6 or not request.otp.isdigit():
        raise HTTPException(status_code=status.HTTP_400_BAD_REQUEST, detail="Invalid OTP format")
    
    # Validate password
    password = validate_password(request.new_password)
    
    try:
        user = db.get_user_by_email(email)
        
        if not user:
            raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail="User not found")
        
        # Verify OTP with password_reset purpose
        try:
            user_data = db.verify_otp(user.id, request.otp, purpose=OTPPurpose.password_reset)
        except Exception as e:
            error_message = str(e).lower()
            if "invalid or expired" in error_message:
                raise HTTPException(status_code=status.HTTP_401_UNAUTHORIZED, detail="Invalid or expired OTP")
            raise HTTPException(status_code=status.HTTP_500_INTERNAL_SERVER_ERROR, detail=f"Failed to verify OTP: {str(e)}")
        
        hashed_password = hash_password(password)
        
        try:
            reset_password = db.reset_user_password(user_data.id, hashed_password)
        except Exception as e:
            error_message = str(e).lower()
            if "email authentication not found" in error_message:
                raise HTTPException(status_code=status.HTTP_400_BAD_REQUEST, detail="Email authentication not found. Cannot reset password for this account.")
            raise HTTPException(status_code=status.HTTP_500_INTERNAL_SERVER_ERROR, detail=f"Failed to reset password: {str(e)}")
        
        return {
            "message": "Password reset successfully. Please login with your new password."
        }
    except HTTPException:
        raise
    except Exception as e:
        raise HTTPException(status_code=status.HTTP_500_INTERNAL_SERVER_ERROR, detail=f"Failed to reset password: {str(e)}")