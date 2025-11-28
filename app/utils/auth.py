from passlib.context import CryptContext
import jwt, secrets, hashlib
from datetime import datetime, timedelta
from sendgrid import SendGridAPIClient
from sendgrid.helpers.mail import Mail
from authlib.integrations.starlette_client import OAuth

from app.core.config import settings


password_context = CryptContext(schemes=["bcrypt"], deprecated="auto")

oauth = OAuth()
oauth.register(
    name="google",
    client_id=settings.GOOGLE_CLIENT_ID,
    client_secret=settings.GOOGLE_CLIENT_SECRET,
    server_metadata_url="https://accounts.google.com/.well-known/openid-configuration",
    client_kwargs={"scope": "openid email profile"},
)

oauth.register(
    name="github",
    client_id=settings.GITHUB_CLIENT_ID,
    client_secret=settings.GITHUB_CLIENT_SECRET,
    access_token_url="https://github.com/login/oauth/access_token",
    authorize_url="https://github.com/login/oauth/authorize",
    api_base_url="https://api.github.com/",
    client_kwargs={"scope": "user:email"},
)

def hash_password(password):
    return password_context.hash(password)

def verify_password(plain_password, hashed_password):
    return password_context.verify(plain_password, hashed_password)

def create_access_token(data: dict):
    to_encode = data.copy()
    expire = datetime.now() + timedelta(minutes=settings.ACCESS_TOKEN_EXPIRE_MINUTES)
    to_encode.update({"exp": expire.timestamp()})
    return jwt.encode(to_encode, settings.JWT_SECRET_KEY, algorithm=settings.JWT_ALGORITHM)

def verify_token(token: str):
    try:
        payload = jwt.decode(token, settings.JWT_SECRET_KEY, algorithms=[settings.JWT_ALGORITHM]) 
        return payload
    except jwt.ExpiredSignatureError:
        return None  # expired
    except jwt.InvalidTokenError:
        return None  # invalid

def create_refresh_token():
    return secrets.token_urlsafe(32)

def hash_refresh_token(token: str):
    return hashlib.sha256(token.encode()).hexdigest()

def send_email_password_reset_link(to_email: str, token: str):
    message = Mail(
        from_email=settings.SENDGRID_FROM_EMAIL,
        to_emails=to_email,
        subject="Your Password Reset link",
        html_content=f"""
        <h3>Welcome to NutureBot</h3>
        <p>Your password reset link is: <b>http://localhost:8000/auth/reset-password/{token}</b></p>
        <p>This code will expire in 15 minutes.</p>
        """
    )
    try:
        sg = SendGridAPIClient(settings.SENDGRID_API_KEY)
        response = sg.send(message)
        print(f"Password reset link sent to {to_email}, Status: {response.status_code}")
    except Exception as e:
        print(f"Failed to send Password reset link: {str(e)}")