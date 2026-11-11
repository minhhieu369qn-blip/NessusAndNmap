"""
connection.py - Kết nối Microsoft SQL Server với cơ chế kiểm tra an toàn.

Cung cấp:
  - test_connection()   : kiểm tra kết nối, trả về (ok, message)
  - get_engine()        : trả về SQLAlchemy engine (singleton)
  - get_pyodbc_conn()   : trả về pyodbc connection thô
"""

import pyodbc
from sqlalchemy import create_engine, text
from sqlalchemy.engine import Engine
from urllib.parse import quote_plus

import sys, os
sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
from config import Settings

# ── Module-level singleton ──────────────────────────────────
_engine: Engine | None = None


def _build_connection_string(database: str | None = None) -> str:
    """Xây dựng chuỗi kết nối pyodbc. Nếu database=None thì dùng DB_NAME từ config."""
    db = database or Settings.DB_NAME
    if Settings.DB_USER and Settings.DB_PASSWORD:
        return (
            f"DRIVER={{{Settings.DB_DRIVER}}};"
            f"SERVER={Settings.DB_SERVER};"
            f"DATABASE={db};"
            f"UID={Settings.DB_USER};"
            f"PWD={Settings.DB_PASSWORD};"
            "TrustServerCertificate=yes;"
        )
    return (
        f"DRIVER={{{Settings.DB_DRIVER}}};"
        f"SERVER={Settings.DB_SERVER};"
        f"DATABASE={db};"
        "Trusted_Connection=yes;"
        "TrustServerCertificate=yes;"
    )


def test_connection(database: str | None = None) -> tuple[bool, str]:
    """
    Kiểm tra kết nối SQL Server.

    Returns:
        (True, "Kết nối thành công ...") hoặc (False, "Chi tiết lỗi ...")
    """
    conn_str = _build_connection_string(database)
    try:
        conn = pyodbc.connect(conn_str, timeout=10)
        cursor = conn.cursor()
        cursor.execute("SELECT @@VERSION")
        version = cursor.fetchone()[0]
        conn.close()
        return True, f"✅ Kết nối thành công!\nSQL Server: {version.split(chr(10))[0]}"
    except pyodbc.InterfaceError as e:
        return False, (
            f"❌ Không tìm thấy ODBC Driver.\n"
            f"Driver đang dùng: {Settings.DB_DRIVER}\n"
            f"Chi tiết: {e}\n\n"
            "💡 Hãy cài đặt Microsoft ODBC Driver for SQL Server:\n"
            "   https://learn.microsoft.com/en-us/sql/connect/odbc/download-odbc-driver-for-sql-server"
        )
    except pyodbc.OperationalError as e:
        return False, (
            f"❌ Không thể kết nối đến SQL Server.\n"
            f"Server: {Settings.DB_SERVER}\n"
            f"Database: {database or Settings.DB_NAME}\n"
            f"Chi tiết: {e}\n\n"
            "💡 Kiểm tra:\n"
            "   1. SQL Server đã bật và đang chạy.\n"
            "   2. Tên server/instance đúng (ví dụ: localhost\\SQLEXPRESS).\n"
            "   3. Firewall cho phép cổng 1433.\n"
            "   4. Nếu dùng SQL Auth, kiểm tra lại DB_USER và DB_PASSWORD."
        )
    except Exception as e:
        return False, f"❌ Lỗi không xác định khi kết nối DB:\n{type(e).__name__}: {e}"


def get_pyodbc_conn(database: str | None = None, autocommit: bool = False) -> pyodbc.Connection:
    """Trả về pyodbc connection. Raise RuntimeError nếu không kết nối được."""
    ok, msg = test_connection(database)
    if not ok:
        raise RuntimeError(msg)
    conn_str = _build_connection_string(database)
    return pyodbc.connect(conn_str, autocommit=autocommit)


def get_engine() -> Engine:
    """Trả về SQLAlchemy Engine singleton. Raise RuntimeError nếu DB không khả dụng."""
    global _engine
    if _engine is not None:
        return _engine

    ok, msg = test_connection()
    if not ok:
        raise RuntimeError(msg)

    conn_str = _build_connection_string()
    encoded = quote_plus(conn_str)
    _engine = create_engine(
        f"mssql+pyodbc:///?odbc_connect={encoded}",
        pool_pre_ping=True,
        pool_recycle=3600,
    )
    return _engine


def execute_raw_sql(sql: str, database: str | None = None) -> None:
    """Thực thi câu lệnh SQL thô (dùng cho setup schema). Tự commit."""
    conn = get_pyodbc_conn(database, autocommit=True)
    cursor = conn.cursor()
    # Tách các lệnh bằng GO (batch separator)
    batches = sql.split("\nGO\n") if "\nGO\n" in sql else [sql]
    for batch in batches:
        batch = batch.strip()
        if batch:
            try:
                cursor.execute(batch)
            except Exception as e:
                # Bỏ qua lỗi nếu object đã tồn tại
                if "already exists" in str(e).lower() or "already an object" in str(e).lower():
                    continue
                raise
    conn.close()
