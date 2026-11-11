"""
nessus_parser.py - Trích xuất dữ liệu từ file .nessus (XML) và .csv.

Trả về DataFrame chuẩn hóa để import vào DB.
"""

import io
from pathlib import Path
from typing import Optional
from datetime import datetime

import pandas as pd
import defusedxml.ElementTree as ET


# Mapping severity number → label
SEVERITY_MAP = {0: "Info", 1: "Low", 2: "Medium", 3: "High", 4: "Critical"}


def _safe_text(element, tag: str, default: str = "") -> str:
    """Trích xuất text an toàn từ XML element."""
    child = element.find(tag)
    if child is not None and child.text:
        return child.text.strip()
    return default


def _safe_float(value: str) -> Optional[float]:
    """Chuyển đổi sang float an toàn."""
    try:
        return float(value) if value else None
    except (ValueError, TypeError):
        return None


def _safe_int(value: str) -> Optional[int]:
    """Chuyển đổi sang int an toàn."""
    try:
        return int(value) if value else None
    except (ValueError, TypeError):
        return None


def parse_nessus_xml(file_content: bytes | str, filename: str = "") -> dict:
    """
    Parse file .nessus (XML) và trả về dict gồm:
      - "metadata": dict chứa thông tin scan (scan_name, policy, scanner, scan_date, ...)
      - "vulnerabilities": pd.DataFrame chứa các lỗ hổng
    """
    if isinstance(file_content, str):
        file_content = file_content.encode("utf-8")

    tree = ET.fromstring(file_content)

    # ── Metadata từ thẻ <Policy> và <Report> ──
    metadata = {
        "scan_name": "",
        "scanner_name": "Nessus",
        "policy_name": "",
        "scan_date": None,
        "source_file": filename,
        "file_type": "nessus",
    }

    # Lấy tên report
    report = tree.find(".//Report")
    if report is not None:
        metadata["scan_name"] = report.get("name", filename)

    # Lấy tên policy
    policy_name_el = tree.find(".//Policy/policyName")
    if policy_name_el is not None and policy_name_el.text:
        metadata["policy_name"] = policy_name_el.text.strip()

    # ── Parse từng ReportHost ──
    vulns_list = []
    hosts_set = set()

    for host_block in tree.findall(".//ReportHost"):
        host_name = host_block.get("name", "unknown")
        hosts_set.add(host_name)

        # Lấy IP từ HostProperties
        host_ip = host_name
        host_fqdn = ""
        for tag_el in host_block.findall(".//HostProperties/tag"):
            tag_name = tag_el.get("name", "")
            if tag_name == "host-ip" and tag_el.text:
                host_ip = tag_el.text.strip()
            elif tag_name == "host-fqdn" and tag_el.text:
                host_fqdn = tag_el.text.strip()
            elif tag_name == "HOST_START" and tag_el.text:
                try:
                    metadata["scan_date"] = datetime.strptime(
                        tag_el.text.strip(), "%a %b %d %H:%M:%S %Y"
                    )
                except ValueError:
                    pass

        # Parse từng ReportItem (mỗi item = 1 lỗ hổng)
        for item in host_block.findall("ReportItem"):
            severity = _safe_int(item.get("severity", "0")) or 0
            plugin_id = _safe_int(item.get("pluginID", "0")) or 0

            # Trích xuất CVE
            cve_elements = item.findall("cve")
            cve_list = ", ".join(
                [cve.text.strip() for cve in cve_elements if cve.text]
            )

            vuln = {
                "host_ip": host_ip,
                "host_name": host_fqdn or host_name,
                "port": _safe_int(item.get("port", "0")),
                "protocol": item.get("protocol", ""),
                "service_name": item.get("svc_name", ""),
                "plugin_id": plugin_id,
                "plugin_name": item.get("pluginName", ""),
                "plugin_family": item.get("pluginFamily", ""),
                "severity": severity,
                "severity_label": SEVERITY_MAP.get(severity, "Info"),
                "cvss_base_score": _safe_float(_safe_text(item, "cvss_base_score")),
                "cvss3_base_score": _safe_float(_safe_text(item, "cvss3_base_score")),
                "cve_list": cve_list,
                "synopsis": _safe_text(item, "synopsis"),
                "description": _safe_text(item, "description"),
                "solution": _safe_text(item, "solution"),
                "plugin_output": _safe_text(item, "plugin_output"),
                "see_also": _safe_text(item, "see_also"),
                "exploit_available": _safe_text(item, "exploit_available").lower() == "true",
                "exploitability_ease": _safe_text(item, "exploitability_ease"),
                "patch_pub_date": _safe_text(item, "patch_publication_date") or None,
                "vuln_pub_date": _safe_text(item, "vuln_publication_date") or None,
            }
            vulns_list.append(vuln)

    df = pd.DataFrame(vulns_list) if vulns_list else pd.DataFrame()
    metadata["total_hosts"] = len(hosts_set)
    metadata["total_vulns"] = len(vulns_list)

    return {"metadata": metadata, "vulnerabilities": df}


def parse_nessus_csv(file_content: bytes | str, filename: str = "") -> dict:
    """
    Parse file CSV xuất từ Nessus.

    Nessus CSV thường có các cột:
      Plugin ID, CVE, CVSS v2.0 Base Score, Risk, Host, Protocol, Port,
      Name, Synopsis, Description, Solution, See Also, Plugin Output

    Trả về dict tương tự parse_nessus_xml.
    """
    if isinstance(file_content, bytes):
        file_content = file_content.decode("utf-8", errors="replace")

    df_raw = pd.read_csv(io.StringIO(file_content))

    # Chuẩn hóa tên cột (lowercase, strip, thay khoảng trắng bằng _)
    df_raw.columns = [
        c.strip().lower().replace(" ", "_").replace(".", "_") for c in df_raw.columns
    ]

    # Mapping tên cột phổ biến từ Nessus CSV
    col_map = {
        "plugin_id": "plugin_id",
        "plugin": "plugin_id",
        "cve": "cve_list",
        "cvss_v2_0_base_score": "cvss_base_score",
        "cvss_v3_0_base_score": "cvss3_base_score",
        "cvss3_base_score": "cvss3_base_score",
        "risk": "severity_label",
        "host": "host_ip",
        "ip": "host_ip",
        "protocol": "protocol",
        "port": "port",
        "name": "plugin_name",
        "plugin_name": "plugin_name",
        "synopsis": "synopsis",
        "description": "description",
        "solution": "solution",
        "see_also": "see_also",
        "plugin_output": "plugin_output",
        "plugin_family": "plugin_family",
    }

    rename_dict = {}
    for csv_col in df_raw.columns:
        if csv_col in col_map:
            rename_dict[csv_col] = col_map[csv_col]

    df_raw.rename(columns=rename_dict, inplace=True)

    # Ánh xạ severity_label → severity number
    risk_to_severity = {
        "none": 0, "info": 0, "informational": 0,
        "low": 1, "medium": 2, "high": 3, "critical": 4,
    }

    if "severity_label" in df_raw.columns:
        df_raw["severity"] = df_raw["severity_label"].fillna("Info").str.lower().map(
            risk_to_severity
        ).fillna(0).astype(int)
        df_raw["severity_label"] = df_raw["severity"].map(SEVERITY_MAP)
    elif "severity" not in df_raw.columns:
        df_raw["severity"] = 0
        df_raw["severity_label"] = "Info"

    # Đảm bảo các cột cần thiết
    for col in ["host_ip", "plugin_id", "plugin_name"]:
        if col not in df_raw.columns:
            df_raw[col] = "" if col != "plugin_id" else 0

    if "host_name" not in df_raw.columns:
        df_raw["host_name"] = df_raw.get("host_ip", "")

    # Xử lý exploit_available
    if "exploit_available" not in df_raw.columns:
        df_raw["exploit_available"] = False

    hosts = df_raw["host_ip"].nunique() if "host_ip" in df_raw.columns else 0

    metadata = {
        "scan_name": Path(filename).stem if filename else "CSV Import",
        "scanner_name": "Nessus",
        "policy_name": "",
        "scan_date": None,
        "source_file": filename,
        "file_type": "csv",
        "total_hosts": hosts,
        "total_vulns": len(df_raw),
    }

    return {"metadata": metadata, "vulnerabilities": df_raw}


def parse_file(file_content: bytes | str, filename: str) -> dict:
    """
    Tự động phát hiện loại file và parse.

    Args:
        file_content: Nội dung file (bytes hoặc string)
        filename: Tên file gốc

    Returns:
        dict {"metadata": {...}, "vulnerabilities": pd.DataFrame}
    """
    ext = Path(filename).suffix.lower()

    if ext == ".nessus":
        return parse_nessus_xml(file_content, filename)
    elif ext == ".csv":
        return parse_nessus_csv(file_content, filename)
    else:
        raise ValueError(
            f"Định dạng file không được hỗ trợ: '{ext}'. "
            "Chỉ hỗ trợ .nessus (XML) và .csv"
        )
