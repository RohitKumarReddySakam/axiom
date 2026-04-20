import os

class Config:
    SECRET_KEY = os.environ.get("SECRET_KEY", "axiom-dev-2025")
    SQLALCHEMY_DATABASE_URI = os.environ.get("DATABASE_URL", "sqlite:///axiom.db")
    SQLALCHEMY_TRACK_MODIFICATIONS = False
    UPLOAD_FOLDER = "uploads"
    MAX_CONTENT_LENGTH = 50 * 1024 * 1024  # 50MB
    # Anomaly detection threshold (lower = more sensitive)
    ANOMALY_THRESHOLD = float(os.environ.get("ANOMALY_THRESHOLD", "0.15"))
