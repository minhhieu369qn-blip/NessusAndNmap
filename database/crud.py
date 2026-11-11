"""
crud.py - Các hàm CRUD (Create, Read, Update) cho database.
"""

import json
from datetime import datetime
from typing import Optional
import pandas as pd
from sqlalchemy import text

import sys, os
sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
from database.connection import get_engine


# ═══════════════════════════════════════════════════════════
#  SCAN SESSIONS
# ═══════════════════════════════════════════════════════════

def insert_scan_session(
    scan_name: str,
    source_file: str,
    file_type: str,
    scan_date: Optional[datetime] = None,
    scanner_name: Optional[str] = None,
    policy_name: Optional[str] = None,
    total_hosts: int = 0,
    total_vulns: int = 0,
    notes: Optional[str] = None,
) -> int:
    """Thêm phiên quét mới, trả về session ID."""
    engine = get_engine()
    with engine.begin() as conn:
        result = conn.execute(
            text("""
                INSERT INTO scan_sessions
                    (scan_name, scan_date, source_file, file_type,
                     scanner_name, policy_name, total_hosts, total_vulns, notes)
                OUTPUT INSERTED.id
                VALUES
                    (:scan_name, :scan_date, :source_file, :file_type,
                     :scanner_name, :policy_name, :total_hosts, :total_vulns, :notes)
            """),
            {
                "scan_name": scan_name,
                "scan_date": scan_date,
                "source_file": source_file,
                "file_type": file_type,
                "scanner_name": scanner_name,
                "policy_name": policy_name,
                "total_hosts": total_hosts,
                "total_vulns": total_vulns,
                "notes": notes,
            },
        )
        return result.fetchone()[0]


def get_all_scan_sessions() -> pd.DataFrame:
    """Lấy tất cả phiên quét, sắp xếp mới nhất trước."""
    engine = get_engine()
    return pd.read_sql(
        "SELECT * FROM scan_sessions ORDER BY import_date DESC", engine
    )


def get_scan_session_by_id(session_id: int) -> Optional[dict]:
    """Lấy thông tin 1 phiên quét theo ID."""
    engine = get_engine()
    with engine.connect() as conn:
        row = conn.execute(
            text("SELECT * FROM scan_sessions WHERE id = :id"), {"id": session_id}
        ).fetchone()
        if row:
            return dict(row._mapping)
    return None


# ═══════════════════════════════════════════════════════════
#  VULNERABILITIES
# ═══════════════════════════════════════════════════════════

def insert_vulnerabilities_bulk(scan_session_id: int, vulns_df: pd.DataFrame) -> int:
    """
    Chèn hàng loạt lỗ hổng từ DataFrame.
    DataFrame cần có các cột tương ứng bảng vulnerabilities.
    Trả về số bản ghi đã chèn.
    """
    if vulns_df.empty:
        return 0

    engine = get_engine()
    records = vulns_df.copy()
    records["scan_session_id"] = scan_session_id

    # Đảm bảo các cột cần thiết tồn tại
    required_cols = [
        "scan_session_id", "host_ip", "plugin_id", "plugin_name", "severity"
    ]
    for col in required_cols:
        if col not in records.columns:
            raise ValueError(f"DataFrame thiếu cột bắt buộc: {col}")

    # Map cột DataFrame sang tên cột DB
    db_columns = [
        "scan_session_id", "host_ip", "host_name", "port", "protocol",
        "service_name", "plugin_id", "plugin_name", "plugin_family",
        "severity", "severity_label", "cvss_base_score", "cvss3_base_score",
        "cve_list", "synopsis", "description", "solution", "plugin_output",
        "see_also", "exploit_available", "exploitability_ease",
        "patch_pub_date", "vuln_pub_date",
    ]

    # Chỉ giữ các cột có trong DataFrame
    available_cols = [c for c in db_columns if c in records.columns]
    records = records[available_cols]

    # Chèn bằng pandas to_sql
    records.to_sql("vulnerabilities", engine, if_exists="append", index=False)
    return len(records)


def get_vulnerabilities_by_session(session_id: int) -> pd.DataFrame:
    """Lấy tất cả lỗ hổng của 1 phiên quét."""
    engine = get_engine()
    return pd.read_sql(
        text("""
            SELECT * FROM vulnerabilities
            WHERE scan_session_id = :sid
            ORDER BY severity DESC, cvss3_base_score DESC
        """),
        engine,
        params={"sid": session_id},
    )


def get_vulnerability_by_id(vuln_id: int) -> Optional[dict]:
    """Lấy chi tiết 1 lỗ hổng."""
    engine = get_engine()
    with engine.connect() as conn:
        row = conn.execute(
            text("SELECT * FROM vulnerabilities WHERE id = :id"), {"id": vuln_id}
        ).fetchone()
        if row:
            return dict(row._mapping)
    return None


def get_vulnerability_stats(session_id: int) -> pd.DataFrame:
    """Thống kê số lỗ hổng theo mức độ nghiêm trọng."""
    engine = get_engine()
    return pd.read_sql(
        text("""
            SELECT
                severity,
                severity_label,
                COUNT(*) as count,
                COUNT(DISTINCT host_ip) as affected_hosts
            FROM vulnerabilities
            WHERE scan_session_id = :sid
            GROUP BY severity, severity_label
            ORDER BY severity DESC
        """),
        engine,
        params={"sid": session_id},
    )


# ═══════════════════════════════════════════════════════════
#  AI ANALYSES
# ═══════════════════════════════════════════════════════════

def insert_ai_analysis(
    vulnerability_id: int,
    ai_provider: str,
    model_name: str,
    root_cause: Optional[str] = None,
    risk_explanation: Optional[str] = None,
    remediation_steps: Optional[str] = None,
    verification_cmds: Optional[str] = None,
    priority_score: Optional[int] = None,
    additional_notes: Optional[str] = None,
) -> int:
    """Lưu kết quả phân tích AI, trả về analysis ID."""
    engine = get_engine()
    with engine.begin() as conn:
        result = conn.execute(
            text("""
                INSERT INTO ai_analyses
                    (vulnerability_id, ai_provider, model_name,
                     root_cause, risk_explanation, remediation_steps,
                     verification_cmds, priority_score, additional_notes)
                OUTPUT INSERTED.id
                VALUES
                    (:vulnerability_id, :ai_provider, :model_name,
                     :root_cause, :risk_explanation, :remediation_steps,
                     :verification_cmds, :priority_score, :additional_notes)
            """),
            {
                "vulnerability_id": vulnerability_id,
                "ai_provider": ai_provider,
                "model_name": model_name,
                "root_cause": root_cause,
                "risk_explanation": risk_explanation,
                "remediation_steps": remediation_steps,
                "verification_cmds": verification_cmds,
                "priority_score": priority_score,
                "additional_notes": additional_notes,
            },
        )
        return result.fetchone()[0]


def get_ai_analysis_by_vuln(vulnerability_id: int) -> Optional[dict]:
    """Lấy bản phân tích AI mới nhất cho 1 lỗ hổng."""
    engine = get_engine()
    with engine.connect() as conn:
        row = conn.execute(
            text("""
                SELECT TOP 1 * FROM ai_analyses
                WHERE vulnerability_id = :vid
                ORDER BY analyzed_at DESC
            """),
            {"vid": vulnerability_id},
        ).fetchone()
        if row:
            return dict(row._mapping)
    return None


def get_ai_analyses_by_session(session_id: int) -> pd.DataFrame:
    """Lấy tất cả phân tích AI của 1 phiên quét."""
    engine = get_engine()
    return pd.read_sql(
        text("""
            SELECT a.*, v.plugin_name, v.severity_label, v.host_ip
            FROM ai_analyses a
            JOIN vulnerabilities v ON a.vulnerability_id = v.id
            WHERE v.scan_session_id = :sid
            ORDER BY a.priority_score DESC
        """),
        engine,
        params={"sid": session_id},
    )


# ═══════════════════════════════════════════════════════════
#  REMEDIATION TRACKING
# ═══════════════════════════════════════════════════════════

def upsert_remediation_status(
    vulnerability_id: int,
    status: str,
    assigned_to: Optional[str] = None,
    resolution_note: Optional[str] = None,
) -> int:
    """Cập nhật hoặc tạo mới trạng thái khắc phục."""
    engine = get_engine()
    with engine.begin() as conn:
        # Kiểm tra đã có chưa
        existing = conn.execute(
            text("SELECT id FROM remediation_tracking WHERE vulnerability_id = :vid"),
            {"vid": vulnerability_id},
        ).fetchone()

        now = datetime.utcnow()

        if existing:
            conn.execute(
                text("""
                    UPDATE remediation_tracking SET
                        status = :status,
                        assigned_to = COALESCE(:assigned_to, assigned_to),
                        resolution_note = COALESCE(:resolution_note, resolution_note),
                        started_at = CASE WHEN :status = 'In Progress' AND started_at IS NULL
                                          THEN :now ELSE started_at END,
                        resolved_at = CASE WHEN :status IN ('Fixed','Accepted Risk','False Positive')
                                           THEN :now ELSE resolved_at END,
                        updated_at = :now
                    WHERE vulnerability_id = :vid
                """),
                {
                    "status": status,
                    "assigned_to": assigned_to,
                    "resolution_note": resolution_note,
                    "now": now,
                    "vid": vulnerability_id,
                },
            )
            return existing[0]
        else:
            result = conn.execute(
                text("""
                    INSERT INTO remediation_tracking
                        (vulnerability_id, status, assigned_to, resolution_note,
                         started_at, resolved_at, updated_at)
                    OUTPUT INSERTED.id
                    VALUES
                        (:vid, :status, :assigned_to, :resolution_note,
                         CASE WHEN :status = 'In Progress' THEN :now ELSE NULL END,
                         CASE WHEN :status IN ('Fixed','Accepted Risk','False Positive') THEN :now ELSE NULL END,
                         :now)
                """),
                {
                    "vid": vulnerability_id,
                    "status": status,
                    "assigned_to": assigned_to,
                    "resolution_note": resolution_note,
                    "now": now,
                },
            )
            return result.fetchone()[0]


def get_remediation_overview(session_id: int) -> pd.DataFrame:
    """Tổng quan tiến độ khắc phục cho 1 phiên quét."""
    engine = get_engine()
    return pd.read_sql(
        text("""
            SELECT
                COALESCE(rt.status, 'Open') as status,
                COUNT(*) as count
            FROM vulnerabilities v
            LEFT JOIN remediation_tracking rt ON v.id = rt.vulnerability_id
            WHERE v.scan_session_id = :sid AND v.severity > 0
            GROUP BY COALESCE(rt.status, 'Open')
        """),
        engine,
        params={"sid": session_id},
    )


# ═══════════════════════════════════════════════════════════
#  SCAN COMPARISONS
# ═══════════════════════════════════════════════════════════

def insert_scan_comparison(
    scan_before_id: int,
    scan_after_id: int,
    total_fixed: int,
    total_new: int,
    total_remaining: int,
    summary_json: Optional[str] = None,
    notes: Optional[str] = None,
) -> int:
    """Lưu kết quả so sánh 2 phiên quét."""
    engine = get_engine()
    with engine.begin() as conn:
        result = conn.execute(
            text("""
                INSERT INTO scan_comparisons
                    (scan_before_id, scan_after_id, total_fixed,
                     total_new, total_remaining, summary_json, notes)
                OUTPUT INSERTED.id
                VALUES
                    (:before, :after, :fixed, :new, :remaining, :summary, :notes)
            """),
            {
                "before": scan_before_id,
                "after": scan_after_id,
                "fixed": total_fixed,
                "new": total_new,
                "remaining": total_remaining,
                "summary": summary_json,
                "notes": notes,
            },
        )
        return result.fetchone()[0]


def get_comparison_history() -> pd.DataFrame:
    """Lấy lịch sử so sánh."""
    engine = get_engine()
    return pd.read_sql(
        """
        SELECT c.*,
               sb.scan_name as before_scan_name,
               sa.scan_name as after_scan_name
        FROM scan_comparisons c
        JOIN scan_sessions sb ON c.scan_before_id = sb.id
        JOIN scan_sessions sa ON c.scan_after_id = sa.id
        ORDER BY c.compared_at DESC
        """,
        engine,
    )


# ═══════════════════════════════════════════════════════════
#  RESET / CLEANUP DATA
# ═══════════════════════════════════════════════════════════

def delete_scan_session(session_id: int) -> None:
    """Xóa 1 phiên quét cụ thể cùng các dữ liệu liên quan."""
    engine = get_engine()
    with engine.begin() as conn:
        conn.execute(
            text("DELETE FROM scan_comparisons WHERE scan_before_id = :sid OR scan_after_id = :sid"),
            {"sid": session_id},
        )
        conn.execute(
            text("DELETE FROM scan_sessions WHERE id = :sid"),
            {"sid": session_id},
        )


def reset_all_database_data() -> None:
    """
    Xóa toàn bộ dữ liệu trong cả 5 bảng và đưa bộ đếm ID (IDENTITY) về 0
    để hệ thống trở về trạng thái ban đầu (0 phiên quét, 0 lỗ hổng).
    """
    engine = get_engine()
    with engine.begin() as conn:
        conn.execute(text("DELETE FROM scan_comparisons"))
        conn.execute(text("DELETE FROM remediation_tracking"))
        conn.execute(text("DELETE FROM ai_analyses"))
        conn.execute(text("DELETE FROM vulnerabilities"))
        conn.execute(text("DELETE FROM scan_sessions"))
        # Reset IDENTITY seed về 0 để phiên quét mới bắt đầu lại từ #1
        for tbl in ["scan_comparisons", "remediation_tracking", "ai_analyses", "vulnerabilities", "scan_sessions"]:
            try:
                conn.execute(text(f"DBCC CHECKIDENT ('{tbl}', RESEED, 0)"))
            except Exception:
                pass

