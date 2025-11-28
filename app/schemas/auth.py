from ssl import Purpose
from pydantic import BaseModel, EmailStr, Field
from typing import Optional

class UserRegisterRequest(BaseModel):
    email: EmailStr
    password:str = Field(..., min_length=8)
    first_name: Optional[str] = None
    last_name: Optional[str] = None

class UserLoginRequest(BaseModel):
    email: EmailStr
    password: str

class LoginResponse(BaseModel):
    access_token: str
    refresh_token: str

class UserUpdateProfileRequest(BaseModel):
    first_name: Optional[str] = Field(None, min_length=1)
    last_name: Optional[str] = Field(None, min_length=1)
    
class ChangePasswordRequest(BaseModel):
    current_password: str
    new_password: str = Field(..., min_length=8)
    
class OTPSendRequest(BaseModel):
    email: EmailStr

class VerifyOTPRequest(BaseModel):
    email: EmailStr
    otp: str = Field(..., min_length=6, max_length=6, pattern=r"^\d{6}$")

class ResetPasswordRequest(BaseModel):
    email: EmailStr

class VerifyResetTokenRequest(BaseModel):
    email: EmailStr
    otp: str = Field(..., min_length=6, max_length=6, pattern=r"^\d{6}$")
    new_password: str = Field(..., min_length=8)

