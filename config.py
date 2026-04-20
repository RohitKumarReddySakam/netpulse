import os


class Config:
    SECRET_KEY = os.environ.get("SECRET_KEY", "netpulse-dev-2025")
    SQLALCHEMY_DATABASE_URI = os.environ.get("DATABASE_URL", "sqlite:///netpulse.db")
    SQLALCHEMY_TRACK_MODIFICATIONS = False
    DEMO_MODE = os.environ.get("DEMO_MODE", "true").lower() == "true"
    FLOW_RETENTION_HOURS = int(os.environ.get("FLOW_RETENTION_HOURS", "24"))
