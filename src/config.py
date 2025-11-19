"""
Configuration management using Pydantic settings.
Loads environment variables and provides type-safe config access.
"""
from pydantic_settings import BaseSettings
from pydantic import Field


class Settings(BaseSettings):
    """Application configuration with secure defaults."""
    
    # Application
    app_name: str = Field(default="SecureMessaging")
    debug: bool = Field(default=False)
    secret_key: str = Field(min_length=32)
    
    # Database
    database_url: str = Field(default="sqlite:///./secure_messaging.db")
    
    # JWT Configuration
    jwt_secret_key: str = Field(min_length=32)
    jwt_algorithm: str = Field(default="HS256")
    access_token_expire_minutes: int = Field(default=15)
    refresh_token_expire_days: int = Field(default=7)
    
    # Argon2 Parameters (OWASP recommended minimums)
    argon2_time_cost: int = Field(default=2)  # iterations
    argon2_memory_cost: int = Field(default=65536)  # 64 MB
    argon2_parallelism: int = Field(default=4)  # threads
    
    class Config:
        env_file = ".env"
        case_sensitive = False


# Singleton instance
settings = Settings()
