# server/app/database.py
import os
from sqlmodel import SQLModel, create_engine, Session

DATABASE_URL = os.getenv("DATABASE_URL", "sqlite:///./vajraa.db")

# Setup connection arguments dynamically
connect_args = {}
if DATABASE_URL.startswith("sqlite"):
    connect_args = {"check_same_thread": False}

engine = create_engine(DATABASE_URL, echo=False, connect_args=connect_args)

def create_db_and_tables():
    """Initializes the database schema and creates tables if they do not exist."""
    SQLModel.metadata.create_all(engine)

def get_session():
    """Dependency generator for database sessions in FastAPI endpoints."""
    with Session(engine) as session:
        yield session
