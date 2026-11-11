"""
setup_db.py - Tạo database và toàn bộ 5 bảng trên SQL Server.

Cách dùng:
    python setup_db.py

Script sẽ:
  1. Kiểm tra kết nối đến SQL Server (kết nối vào master trước).
  2. Tạo database NessusAnalyzer nếu chưa có.
  3. Chạy schema.sql để tạo 5 bảng.
"""

import sys
import os
from pathlib import Path

# Đảm bảo import được các module trong project
sys.path.insert(0, str(Path(__file__).resolve().parent))

from config import Settings
from database.connection import test_connection, get_pyodbc_conn


def main():
    print("=" * 60)
    print("  🛡️  NESSUS AI ANALYZER - Database Setup")
    print("=" * 60)
    print()

    # ── Bước 1: Kiểm tra kết nối đến SQL Server (qua master) ──
    print("[1/3] Kiểm tra kết nối SQL Server...")
    ok, msg = test_connection(database="master")
    if not ok:
        print(msg)
        print()
        print("⛔ Không thể tiếp tục. Hãy kiểm tra cấu hình trong file .env")
        sys.exit(1)
    print(msg)
    print()

    # ── Bước 2: Tạo database nếu chưa có ──
    db_name = Settings.DB_NAME
    print(f"[2/3] Tạo database [{db_name}] nếu chưa tồn tại...")
    try:
        conn = get_pyodbc_conn(database="master", autocommit=True)
        cursor = conn.cursor()

        # Kiểm tra database đã tồn tại chưa
        cursor.execute(
            "SELECT COUNT(*) FROM sys.databases WHERE name = ?", db_name
        )
        exists = cursor.fetchone()[0] > 0

        if exists:
            print(f"   ℹ️  Database [{db_name}] đã tồn tại.")
        else:
            cursor.execute(f"CREATE DATABASE [{db_name}]")
            print(f"   ✅ Đã tạo database [{db_name}].")

        conn.close()
    except Exception as e:
        print(f"   ❌ Lỗi khi tạo database: {e}")
        sys.exit(1)
    print()

    # ── Bước 3: Chạy schema.sql tạo 5 bảng ──
    print("[3/3] Tạo các bảng dữ liệu từ schema.sql...")
    schema_path = Path(__file__).resolve().parent / "database" / "schema.sql"

    if not schema_path.exists():
        print(f"   ❌ Không tìm thấy file: {schema_path}")
        sys.exit(1)

    schema_sql = schema_path.read_text(encoding="utf-8")

    try:
        conn = get_pyodbc_conn(database=db_name, autocommit=True)
        cursor = conn.cursor()

        # Tách các câu lệnh SQL (xử lý comment và nhiều statement)
        # Loại bỏ comment dòng bắt đầu bằng --
        lines = schema_sql.split("\n")
        clean_lines = []
        for line in lines:
            stripped = line.strip()
            if stripped.startswith("--"):
                continue
            clean_lines.append(line)

        full_sql = "\n".join(clean_lines)

        # Tách bằng dấu ; ở cuối statement (nhưng giữ nguyên trong CHECK constraint)
        # Dùng phương pháp đơn giản: tách từng khối CREATE/ALTER
        statements = []
        current = []
        for line in full_sql.split("\n"):
            current.append(line)
            if line.strip().endswith(";"):
                statements.append("\n".join(current))
                current = []
        if current:
            remaining = "\n".join(current).strip()
            if remaining:
                statements.append(remaining)

        created_count = 0
        skipped_count = 0
        for stmt in statements:
            stmt = stmt.strip()
            if not stmt:
                continue
            try:
                cursor.execute(stmt)
                created_count += 1
            except Exception as e:
                err_msg = str(e).lower()
                if "already" in err_msg or "there is already" in err_msg:
                    skipped_count += 1
                    continue
                else:
                    print(f"   ⚠️  Lỗi SQL: {e}")
                    print(f"   Statement: {stmt[:200]}...")

        print(f"   ✅ Hoàn tất! Đã thực thi {created_count} lệnh, bỏ qua {skipped_count} (đã tồn tại).")
        conn.close()
    except RuntimeError as e:
        print(f"   ❌ Lỗi kết nối: {e}")
        sys.exit(1)
    except Exception as e:
        print(f"   ❌ Lỗi: {e}")
        sys.exit(1)

    print()
    print("=" * 60)
    print("  🎉 Setup hoàn tất! Bạn có thể chạy ứng dụng:")
    print("     streamlit run app.py")
    print("=" * 60)


if __name__ == "__main__":
    main()
