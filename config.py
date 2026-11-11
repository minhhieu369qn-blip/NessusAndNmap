"""
config.py - Đọc và quản lý cấu hình từ biến môi trường (.env).
"""

import os
from pathlib import Path
from dotenv import load_dotenv

# Tải biến môi trường từ file .env cùng thư mục gốc dự án
_env_path = Path(__file__).resolve().parent / ".env"
load_dotenv(_env_path, override=True)


class Settings:
    """Singleton-like settings object đọc từ biến môi trường."""

    # ── AI ───────────────────────────────────────────────────
    AI_PROVIDER: str = os.getenv("AI_PROVIDER", "gemini").lower()
    GEMINI_API_KEY: str = os.getenv("GEMINI_API_KEY", "")
    OPENAI_API_KEY: str = os.getenv("OPENAI_API_KEY", "")
    AI_MODEL: str = os.getenv("AI_MODEL", "")

    # ── Nessus API ───────────────────────────────────────────
    NESSUS_URL: str = os.getenv("NESSUS_URL", "https://localhost:8834")
    NESSUS_USERNAME: str = os.getenv("NESSUS_USERNAME", "")
    NESSUS_PASSWORD: str = os.getenv("NESSUS_PASSWORD", "")
    NESSUS_ACCESS_KEY: str = os.getenv("NESSUS_ACCESS_KEY", "")
    NESSUS_SECRET_KEY: str = os.getenv("NESSUS_SECRET_KEY", "")

    # ── Database ─────────────────────────────────────────────
    DB_SERVER: str = os.getenv("DB_SERVER", "localhost")
    DB_NAME: str = os.getenv("DB_NAME", "NessusAnalyzer")
    DB_USER: str = os.getenv("DB_USER", "")
    DB_PASSWORD: str = os.getenv("DB_PASSWORD", "")
    DB_DRIVER: str = os.getenv("DB_DRIVER", "ODBC Driver 17 for SQL Server")

    @classmethod
    def get_connection_string(cls) -> str:
        """Trả về chuỗi kết nối pyodbc."""
        if cls.DB_USER and cls.DB_PASSWORD:
            return (
                f"DRIVER={{{cls.DB_DRIVER}}};"
                f"SERVER={cls.DB_SERVER};"
                f"DATABASE={cls.DB_NAME};"
                f"UID={cls.DB_USER};"
                f"PWD={cls.DB_PASSWORD};"
                "TrustServerCertificate=yes;"
            )
        # Windows Authentication
        return (
            f"DRIVER={{{cls.DB_DRIVER}}};"
            f"SERVER={cls.DB_SERVER};"
            f"DATABASE={cls.DB_NAME};"
            "Trusted_Connection=yes;"
            "TrustServerCertificate=yes;"
        )

    @classmethod
    def get_sqlalchemy_url(cls) -> str:
        """Trả về URL cho SQLAlchemy (dùng pyodbc)."""
        params = cls.get_connection_string().replace(";", "&").rstrip("&")
        return f"mssql+pyodbc:///?odbc_connect={params}"

    @classmethod
    def get_active_api_key(cls) -> str:
        """Trả về API key của provider đang chọn."""
        if cls.AI_PROVIDER == "openai":
            return cls.OPENAI_API_KEY
        return cls.GEMINI_API_KEY

    @classmethod
    def get_model_name(cls) -> str:
        """Trả về tên model, hoặc mặc định theo provider."""
        if cls.AI_MODEL:
            return cls.AI_MODEL
        if cls.AI_PROVIDER == "openai":
            return "gpt-4o"
        return "gemini-3.1-flash-lite"

    @classmethod
    def validate(cls) -> list[str]:
        """Kiểm tra cấu hình và trả về danh sách lỗi (rỗng = hợp lệ)."""
        errors: list[str] = []
        if not cls.get_active_api_key():
            errors.append(
                f"Chưa cấu hình API key cho provider '{cls.AI_PROVIDER}'. "
                f"Hãy điền {'GEMINI_API_KEY' if cls.AI_PROVIDER == 'gemini' else 'OPENAI_API_KEY'} trong file .env"
            )
        if not cls.DB_SERVER:
            errors.append("Chưa cấu hình DB_SERVER trong file .env")
        return errors
