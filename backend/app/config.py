import os
from dotenv import load_dotenv

# Load local .env file if it exists
load_dotenv()

DATABASE_URL = os.getenv("DATABASE_URL", "sqlite:///./predictions.db")

# SQLAlchemy requires postgresql+psycopg2:// to use psycopg2 driver on PostgreSQL
if DATABASE_URL:
    if DATABASE_URL.startswith("postgres://"):
        DATABASE_URL = DATABASE_URL.replace("postgres://", "postgresql+psycopg2://", 1)
    elif DATABASE_URL.startswith("postgresql+psycopg://"):
        DATABASE_URL = DATABASE_URL.replace("postgresql+psycopg://", "postgresql+psycopg2://", 1)
    elif DATABASE_URL.startswith("postgresql://"):
        DATABASE_URL = DATABASE_URL.replace("postgresql://", "postgresql+psycopg2://", 1)

