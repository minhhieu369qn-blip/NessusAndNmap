"""
comparator.py - So sánh kết quả giữa 2 lần quét Nessus.

Phân loại lỗ hổng thành 3 nhóm:
  - Fixed:     Có trong lần quét trước, KHÔNG còn trong lần quét sau.
  - New:       KHÔNG có trong lần quét trước, xuất hiện mới trong lần quét sau.
  - Remaining: Có trong CẢ 2 lần quét (chưa được khắc phục).

Logic so sánh dựa trên bộ khóa: (host_ip, plugin_id, port)
"""

import json
from typing import Optional
import pandas as pd

import sys, os
sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
from database.crud import (
    get_vulnerabilities_by_session,
    insert_scan_comparison,
    get_scan_session_by_id,
)


def _make_vuln_key(row: pd.Series) -> str:
    """Tạo khóa duy nhất cho 1 lỗ hổng dựa trên host_ip + plugin_id + port."""
    return f"{row.get('host_ip', '')}|{row.get('plugin_id', '')}|{row.get('port', '')}"


def compare_scans(
    before_session_id: int,
    after_session_id: int,
    save_to_db: bool = True,
    include_info: bool = False,
) -> dict:
    """
    So sánh 2 phiên quét và phân loại lỗ hổng.

    Args:
        before_session_id: ID phiên quét TRƯỚC khi khắc phục
        after_session_id:  ID phiên quét SAU khi khắc phục
        save_to_db:        Có lưu kết quả vào bảng scan_comparisons không

    Returns:
        dict {
            "fixed": pd.DataFrame,        # Lỗ hổng đã khắc phục
            "new": pd.DataFrame,           # Lỗ hổng mới phát sinh
            "remaining": pd.DataFrame,     # Lỗ hổng còn tồn tại
            "summary": {
                "total_fixed": int,
                "total_new": int,
                "total_remaining": int,
                "fixed_by_severity": dict,
                "new_by_severity": dict,
                "remaining_by_severity": dict,
                "fix_rate_percent": float,
            },
            "comparison_id": int | None,
        }
    """
    # Lấy dữ liệu lỗ hổng từ 2 phiên quét
    df_before_all = get_vulnerabilities_by_session(before_session_id)
    df_after_all = get_vulnerabilities_by_session(after_session_id)

    # Tùy chọn bỏ qua Info hoặc giữ cả Info (hữu ích khi đối chiếu Black-Box vs White-Box 47 mục)
    if include_info:
        df_before = df_before_all.copy()
        df_after = df_after_all.copy()
    else:
        df_before = df_before_all[df_before_all["severity"] > 0].copy() if not df_before_all.empty else pd.DataFrame()
        df_after = df_after_all[df_after_all["severity"] > 0].copy() if not df_after_all.empty else pd.DataFrame()

    # Tạo khóa so sánh
    before_keys = set(df_before.apply(_make_vuln_key, axis=1)) if not df_before.empty else set()
    after_keys = set(df_after.apply(_make_vuln_key, axis=1)) if not df_after.empty else set()

    # Phân loại
    fixed_keys = before_keys - after_keys
    new_keys = after_keys - before_keys
    remaining_keys = before_keys & after_keys

    # Thêm cột key vào DataFrame để filter
    if not df_before.empty:
        df_before["_key"] = df_before.apply(_make_vuln_key, axis=1)
    if not df_after.empty:
        df_after["_key"] = df_after.apply(_make_vuln_key, axis=1)

    df_fixed = df_before[df_before["_key"].isin(fixed_keys)].copy() if not df_before.empty else pd.DataFrame()
    df_new = df_after[df_after["_key"].isin(new_keys)].copy() if not df_after.empty else pd.DataFrame()
    df_remaining = df_after[df_after["_key"].isin(remaining_keys)].copy() if not df_after.empty else pd.DataFrame()

    # Xóa cột tạm
    for df in [df_before, df_after, df_fixed, df_new, df_remaining]:
        if "_key" in df.columns:
            df.drop(columns=["_key"], inplace=True)

    # Thống kê theo severity
    def severity_counts(df: pd.DataFrame) -> dict:
        if df.empty:
            return {"Critical": 0, "High": 0, "Medium": 0, "Low": 0, "Info": 0}
        counts = df["severity_label"].value_counts().to_dict()
        return {
            "Critical": counts.get("Critical", 0),
            "High": counts.get("High", 0),
            "Medium": counts.get("Medium", 0),
            "Low": counts.get("Low", 0),
            "Info": counts.get("Info", 0),
        }

    total_before = len(before_keys)
    total_fixed = len(fixed_keys)
    fix_rate = (total_fixed / total_before * 100) if total_before > 0 else 0.0

    summary = {
        "total_before": total_before,
        "total_after": len(after_keys),
        "total_before_all_records": len(df_before_all),
        "total_after_all_records": len(df_after_all),
        "total_fixed": total_fixed,
        "total_new": len(new_keys),
        "total_remaining": len(remaining_keys),
        "before_by_severity": severity_counts(df_before_all if include_info else df_before),
        "after_by_severity": severity_counts(df_after_all if include_info else df_after),
        "fixed_by_severity": severity_counts(df_fixed),
        "new_by_severity": severity_counts(df_new),
        "remaining_by_severity": severity_counts(df_remaining),
        "fix_rate_percent": round(fix_rate, 1),
    }

    # Lưu vào DB nếu cần
    comparison_id = None
    if save_to_db:
        try:
            comparison_id = insert_scan_comparison(
                scan_before_id=before_session_id,
                scan_after_id=after_session_id,
                total_fixed=total_fixed,
                total_new=len(new_keys),
                total_remaining=len(remaining_keys),
                summary_json=json.dumps(summary, ensure_ascii=False),
            )
        except Exception:
            pass  # Không block nếu DB lỗi

    return {
        "fixed": df_fixed,
        "new": df_new,
        "remaining": df_remaining,
        "summary": summary,
        "comparison_id": comparison_id,
    }


def generate_comparison_report_text(comparison: dict) -> str:
    """
    Tạo bản báo cáo text từ kết quả so sánh.

    Args:
        comparison: dict trả về từ compare_scans()

    Returns:
        str: Báo cáo dạng text có thể hiển thị hoặc xuất file.
    """
    s = comparison["summary"]

    lines = [
        "═" * 60,
        "  📊 BÁO CÁO SO SÁNH KẾT QUẢ QUÉT LỖ HỔNG",
        "═" * 60,
        "",
        f"  Lỗ hổng trước khắc phục : {s['total_before']}",
        f"  Lỗ hổng sau khắc phục  : {s['total_after']}",
        f"  Tỷ lệ khắc phục        : {s['fix_rate_percent']}%",
        "",
        "─" * 40,
        f"  ✅ ĐÃ KHẮC PHỤC (Fixed)  : {s['total_fixed']}",
    ]

    for sev, count in s["fixed_by_severity"].items():
        if count > 0:
            lines.append(f"     • {sev}: {count}")

    lines.extend([
        "",
        f"  🆕 MỚI PHÁT SINH (New)   : {s['total_new']}",
    ])
    for sev, count in s["new_by_severity"].items():
        if count > 0:
            lines.append(f"     • {sev}: {count}")

    lines.extend([
        "",
        f"  ⚠️  CÒN TỒN TẠI (Remaining): {s['total_remaining']}",
    ])
    for sev, count in s["remaining_by_severity"].items():
        if count > 0:
            lines.append(f"     • {sev}: {count}")

    lines.extend(["", "═" * 60])

    return "\n".join(lines)


def generate_security_certificate_html(
    comparison: dict,
    before_name: str,
    after_name: str,
    target_ip: str = "192.168.104.129",
) -> str:
    """
    Sinh Chứng chỉ Xác nhận Hoàn tất Khắc phục An toàn (Security Closed-Loop Certificate) dạng HTML.
    """
    from datetime import datetime
    s = comparison["summary"]
    now_str = datetime.now().strftime("%d/%m/%Y %H:%M:%S")
    rem_crit = s["remaining_by_severity"].get("Critical", 0)
    rem_high = s["remaining_by_severity"].get("High", 0)
    rem_med = s["remaining_by_severity"].get("Medium", 0)
    status_badge = "SAFE / PASSED (ĐẠT CHUẨN AN TOÀN)" if (rem_crit == 0 and rem_high == 0) else "CONDITIONAL / PENDING"
    badge_color = "#2E7D32" if (rem_crit == 0 and rem_high == 0) else "#F9A825"

    return f"""<!DOCTYPE html>
<html lang="vi">
<head>
<meta charset="UTF-8">
<title>Chứng nhận Hoàn tất Khắc phục Lỗ hổng - {target_ip}</title>
<style>
  body {{ font-family: 'Segoe UI', Arial, sans-serif; background: #f8fafc; color: #0f172a; padding: 24px; }}
  .cert-box {{ max-width: 820px; margin: auto; background: #ffffff; border: 3px solid #0284c7; border-radius: 14px; padding: 32px; box-shadow: 0 8px 24px rgba(15,23,42,0.08); }}
  .title {{ text-align: center; color: #0369a1; font-size: 25px; font-weight: bold; text-transform: uppercase; letter-spacing: 0.8px; }}
  .subtitle {{ text-align: center; color: #475569; font-size: 14px; margin-top: 6px; margin-bottom: 20px; }}
  .badge {{ display: block; width: fit-content; margin: 14px auto; background: {badge_color}; color: white; padding: 10px 26px; border-radius: 30px; font-weight: bold; font-size: 17px; }}
  table {{ width: 100%; border-collapse: collapse; margin-top: 18px; }}
  th, td {{ border: 1px solid #cbd5e1; padding: 11px 14px; text-align: left; color: #0f172a; }}
  th {{ background: #f1f5f9; color: #0369a1; font-weight: 700; }}
  .footer {{ margin-top: 24px; text-align: center; font-size: 13px; color: #475569; border-top: 1px solid #cbd5e1; padding-top: 14px; }}
</style>
</head>
<body>
  <div class="cert-box">
    <div class="title">🛡️ CHỨNG NHẬN NGHIỆM THU AN TOÀN THÔNG TIN</div>
    <div class="subtitle">HỆ THỐNG DASHBOARD PHÂN TÍCH LỖ HỔNG & TỰ ĐỘNG HÓA KHẮC PHỤC BẰNG AI (TENABLE NESSUS & NMAP)</div>
    <div class="badge">TRẠNG THÁI: {status_badge}</div>
    <table>
      <tr><th>Thông số Kiểm định</th><th>Chi tiết Ghi nhận</th></tr>
      <tr><td>Máy mục tiêu (Target Host)</td><td><b>{target_ip}</b> (Windows 11 Pro Build 26200 - VMware NAT 192.168.104.0/24)</td></tr>
      <tr><td>Máy dò quét (Scanner Engine)</td><td>192.168.104.1 (Tenable Nessus Engine + Nmap NSE + AI Security Assistant)</td></tr>
      <tr><td>Phiên quét Trước khi vá (Baseline)</td><td>{before_name} ({s['total_before']} lỗ hổng)</td></tr>
      <tr><td>Phiên quét Kiểm chứng (Validation)</td><td>{after_name} ({s['total_after']} lỗ hổng)</td></tr>
      <tr><td>Số lỗ hổng đã triệt tiêu (Fixed)</td><td><b style="color:#15803d;">{s['total_fixed']} lỗ hổng</b> (Tỷ lệ khắc phục: <b>{s['fix_rate_percent']}%</b>)</td></tr>
      <tr><td>Lỗ hổng Critical / High / Medium còn sót</td><td>Critical: <b>{rem_crit}</b> | High: <b>{rem_high}</b> | Medium: <b>{rem_med}</b></td></tr>
      <tr><td>Thời điểm cấp chứng nhận</td><td>{now_str}</td></tr>
    </table>
    <div class="footer">
      Xác thực tự động bởi <b>Nessus & Nmap AI Security Closed-Loop Engine (Phương án A)</b> — Học phần Bảo đảm và An toàn Thông tin.
    </div>
  </div>
</body>
</html>"""

