from pydantic_settings import BaseSettings

class Settings(BaseSettings):
    # Project
    PROJECT_NAME: str = "NutureBot"
    DEBUG: bool = True

    # Database
    SYNC_CONNECTION_STRING: str
    # SUPABASE_URL: str
    SUPABASE_KEY: str

    # JWT Configuration
    JWT_SECRET_KEY: str
    JWT_ALGORITHM: str = "HS256"
    ACCESS_TOKEN_EXPIRE_MINUTES: int = 30
    REFRESH_TOKEN_EXPIRE_DAYS: int = 7

    # OAuth Credentials - Google
    GOOGLE_CLIENT_ID: str
    GOOGLE_CLIENT_SECRET: str
    GOOGLE_REDIRECT_URI: str

    # OAuth Credentials - GitHub
    GITHUB_CLIENT_ID: str
    GITHUB_CLIENT_SECRET: str
    GITHUB_REDIRECT_URI: str

    # Email (SendGrid)
    SENDGRID_API_KEY: str
    SENDGRID_FROM_EMAIL: str

    # AI API Key
    GOOGLE_API_KEY: str
    GOOGLE_EMBEDDING_MODEL: str = "gemini-embedding-001"
    GOOGLE_CHAT_MODEL: str = "gemini-2.5-flash"

    class Config:
        env_file = ".env"
        case_sensitive = True


settings = Settings()
