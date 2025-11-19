"""
FastAPI application factory.
"""
from fastapi import FastAPI
from .routes import auth, messages
from .db import init_db

def create_app() -> FastAPI:
    """Create and configure FastAPI application."""
    app = FastAPI(
        title="Secure Messaging API",
        description="End-to-end encrypted messaging with ECDH + AES-256-GCM",
        version="1.0.0"
    )
    
    # Include routers
    app.include_router(auth.router)
    app.include_router(messages.router)
    
    # Initialize database on startup
    @app.on_event("startup")
    def startup():
        init_db()
    
    return app
