"""
nessus_api.py - Kết nối trực tiếp Nessus Local API (https://localhost:8834).

Hỗ trợ 2 phương thức xác thực:
  1. Username/Password → lấy session token
  2. API Keys (Access Key + Secret Key)

Workflow:
  login → list_scans → get_scan_details → get_host_vulns → DataFrame chuẩn hóa
"""

import warnings
import urllib3
from typing import Optional
from datetime import datetime

import requests
import pandas as pd

# Tắt cảnh báo SSL vì Nessus dùng self-signed cert
urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)
warnings.filterwarnings("ignore", message="Unverified HTTPS request")

# Severity mapping
SEVERITY_MAP = {0: "Info", 1: "Low", 2: "Medium", 3: "High", 4: "Critical"}

# Cột chuẩn của DataFrame vulnerabilities
STANDARD_COLUMNS = [
    "host_ip", "host_name", "port", "protocol", "service_name",
    "plugin_id", "plugin_name", "plugin_family", "severity",
    "severity_label", "cvss_base_score", "cvss3_base_score",
    "cve_list", "synopsis", "description", "solution",
    "plugin_output", "see_also", "exploit_available",
    "exploitability_ease", "patch_pub_date", "vuln_pub_date",
]


def _build_safe_dataframe(records: list[dict]) -> pd.DataFrame:
    """Tạo DataFrame với đầy đủ các cột chuẩn, tránh KeyError khi truy xuất."""
    if not records:
        return pd.DataFrame(columns=STANDARD_COLUMNS)
    df = pd.DataFrame(records)
    for col in STANDARD_COLUMNS:
        if col not in df.columns:
            if col == "severity":
                df[col] = 0
            elif col == "severity_label":
                df[col] = "Info"
            elif col in ("port", "plugin_id"):
                df[col] = 0
            elif col == "exploit_available":
                df[col] = False
            else:
                df[col] = ""
    # Đảm bảo severity là int và severity_label đúng chuẩn
    df["severity"] = pd.to_numeric(df["severity"], errors="coerce").fillna(0).astype(int)
    df["severity_label"] = df["severity"].map(SEVERITY_MAP).fillna("Info")
    return df


class NessusAPIClient:
    """
    Client kết nối Nessus Scanner qua REST API.

    Nessus API docs: https://localhost:8834/api
    Mặc định dùng HTTPS với self-signed certificate (verify=False).
    """

    def __init__(
        self,
        url: str = "https://localhost:8834",
        username: str = "",
        password: str = "",
        access_key: str = "",
        secret_key: str = "",
    ):
        self.base_url = url.rstrip("/")
        self.username = username
        self.password = password
        self.access_key = access_key
        self.secret_key = secret_key
        self.token: Optional[str] = None
        self.session = requests.Session()
        self.session.verify = False  # Nessus dùng self-signed cert
        self.session.timeout = 30

    # ═════════════════════════════════════════════════════════
    #  AUTHENTICATION
    # ═════════════════════════════════════════════════════════

    def _get_headers(self) -> dict:
        """Trả về headers xác thực phù hợp."""
        headers = {"Content-Type": "application/json"}
        if self.access_key and self.secret_key:
            headers["X-ApiKeys"] = f"accessKey={self.access_key};secretKey={self.secret_key}"
        elif self.token:
            headers["X-Cookie"] = f"token={self.token}"
        return headers

    def login(self) -> tuple[bool, str]:
        """
        Xác thực với Nessus.

        - Nếu có API Keys → dùng ngay (không cần login).
        - Nếu có username/password → gọi POST /session lấy token.

        Returns:
            (True, "Thành công...") hoặc (False, "Lỗi...")
        """
        # Phương thức 1: API Keys — chỉ cần kiểm tra kết nối
        if self.access_key and self.secret_key:
            try:
                resp = self.session.get(
                    f"{self.base_url}/server/status",
                    headers=self._get_headers(),
                )
                if resp.status_code == 200:
                    data = resp.json()
                    status = data.get("status", "unknown")
                    return True, f"✅ Kết nối Nessus thành công (API Keys).\nTrạng thái: {status}"
                elif resp.status_code == 401:
                    return False, "❌ API Keys không hợp lệ. Kiểm tra lại Access Key và Secret Key."
                else:
                    return False, f"❌ Lỗi API: HTTP {resp.status_code}\n{resp.text[:500]}"
            except requests.ConnectionError:
                return False, (
                    f"❌ Không thể kết nối đến Nessus tại {self.base_url}\n\n"
                    "💡 Kiểm tra:\n"
                    "  1. Nessus đã khởi động chưa?\n"
                    "  2. URL đúng chưa? (mặc định: https://localhost:8834)\n"
                    "  3. Firewall có chặn cổng 8834 không?"
                )
            except Exception as e:
                return False, f"❌ Lỗi: {type(e).__name__}: {e}"

        # Phương thức 2: Username/Password → POST /session
        if not self.username or not self.password:
            return False, "❌ Chưa nhập thông tin xác thực (username/password hoặc API Keys)."

        try:
            resp = self.session.post(
                f"{self.base_url}/session",
                json={"username": self.username, "password": self.password},
                headers={"Content-Type": "application/json"},
            )

            if resp.status_code == 200:
                data = resp.json()
                self.token = data.get("token", "")
                if self.token:
                    return True, f"✅ Đăng nhập Nessus thành công!\nUser: {self.username}"
                return False, "❌ Đăng nhập thành công nhưng không nhận được token."
            elif resp.status_code == 401:
                return False, "❌ Sai tên đăng nhập hoặc mật khẩu Nessus."
            elif resp.status_code == 400:
                return False, "❌ Yêu cầu không hợp lệ. Kiểm tra lại username/password."
            else:
                return False, f"❌ Lỗi đăng nhập: HTTP {resp.status_code}\n{resp.text[:500]}"

        except requests.ConnectionError:
            return False, (
                f"❌ Không thể kết nối đến Nessus tại {self.base_url}\n\n"
                "💡 Kiểm tra:\n"
                "  1. Nessus đã khởi động và chạy xong initialization chưa?\n"
                "  2. URL đúng chưa? (mặc định: https://localhost:8834)\n"
                "  3. Firewall có chặn cổng 8834 không?"
            )
        except Exception as e:
            return False, f"❌ Lỗi: {type(e).__name__}: {e}"

    def logout(self):
        """Đăng xuất phiên (nếu dùng token)."""
        if self.token:
            try:
                self.session.delete(
                    f"{self.base_url}/session",
                    headers=self._get_headers(),
                )
            except Exception:
                pass
            self.token = None

    # ═════════════════════════════════════════════════════════
    #  API CALLS
    # ═════════════════════════════════════════════════════════

    def _api_get(self, endpoint: str, params: dict = None) -> dict:
        """GET request an toàn đến Nessus API."""
        resp = self.session.get(
            f"{self.base_url}{endpoint}",
            headers=self._get_headers(),
            params=params,
        )
        resp.raise_for_status()
        return resp.json()

    def get_server_info(self) -> dict:
        """Lấy thông tin server Nessus."""
        return self._api_get("/server/properties")

    def list_scans(self) -> list[dict]:
        """
        Lấy danh sách tất cả scans.

        Returns:
            List[dict] - Mỗi dict gồm: id, name, status, creation_date,
                          last_modification_date, folder_id, ...
        """
        data = self._api_get("/scans")
        scans = data.get("scans", [])

        if scans is None:
            return []

        result = []
        for s in scans:
            scan_info = {
                "id": s.get("id"),
                "name": s.get("name", "N/A"),
                "status": s.get("status", "unknown"),
                "folder_id": s.get("folder_id"),
                "creation_date": _timestamp_to_str(s.get("creation_date")),
                "last_modification_date": _timestamp_to_str(s.get("last_modification_date")),
                "total_hosts": s.get("hostcount", 0),
            }
            result.append(scan_info)

        return result

    def get_scan_details(self, scan_id: int) -> dict:
        """
        Lấy chi tiết scan bao gồm danh sách hosts.

        Returns:
            dict với keys: info, hosts, vulnerabilities, ...
        """
        return self._api_get(f"/scans/{scan_id}")

    def get_host_details(self, scan_id: int, host_id: int) -> dict:
        """
        Lấy chi tiết lỗ hổng cho 1 host cụ thể trong scan.

        Returns:
            dict chứa danh sách vulnerabilities của host
        """
        return self._api_get(f"/scans/{scan_id}/hosts/{host_id}")

    def get_plugin_output(self, scan_id: int, host_id: int, plugin_id: int) -> dict:
        """
        Lấy chi tiết output của 1 plugin trên 1 host.

        Returns:
            dict chứa plugin output chi tiết
        """
        return self._api_get(f"/scans/{scan_id}/hosts/{host_id}/plugins/{plugin_id}")

    def launch_scan(self, scan_id: int) -> tuple[bool, str]:
        """
        Kích hoạt chạy lại (Re-scan / Validation Scan) một phiên quét trên Nessus qua REST API.
        Đóng vòng lặp bảo mật (Security Closed-Loop).
        """
        try:
            resp = self.session.post(
                f"{self.base_url}/scans/{scan_id}/launch",
                headers=self._get_headers(),
            )
            if resp.status_code == 200:
                data = resp.json() if resp.text else {}
                scan_uuid = data.get("scan_uuid", "N/A")
                return True, f"🚀 Đã kích hoạt chạy lại Scan #{scan_id} thành công! (UUID: {scan_uuid})"
            return False, f"❌ Không thể kích hoạt Scan #{scan_id}: HTTP {resp.status_code} - {resp.text[:300]}"
        except Exception as e:
            return False, f"❌ Lỗi khi gọi API launch_scan: {type(e).__name__}: {e}"

    # ═════════════════════════════════════════════════════════
    #  HIGH-LEVEL: FETCH TOÀN BỘ KẾT QUẢ QUÉT
    # ═════════════════════════════════════════════════════════

    def fetch_scan_results(
        self,
        scan_id: int,
        include_info: bool = False,
        progress_callback=None,
    ) -> dict:
        """
        Nạp toàn bộ kết quả quét cho 1 scan — format tương thích với nessus_parser.

        Args:
            scan_id:           ID của scan cần lấy dữ liệu
            include_info:      Có lấy lỗ hổng severity=0 (Info) không (mặc định: không)
            progress_callback: Callable(current, total, message) để cập nhật tiến trình

        Returns:
            dict {
                "metadata": { scan_name, scan_date, total_hosts, total_vulns, ... },
                "vulnerabilities": pd.DataFrame
            }
        """
        # 1. Lấy thông tin tổng quan scan
        scan_data = self.get_scan_details(scan_id)
        if not isinstance(scan_data, dict):
            scan_data = {}

        info = scan_data.get("info", {}) if isinstance(scan_data.get("info"), dict) else {}
        hosts = scan_data.get("hosts", []) if isinstance(scan_data.get("hosts"), list) else []

        scan_name = info.get("name", f"Scan #{scan_id}")
        scanner_name = info.get("scanner_name", "Nessus")
        policy_name = info.get("policy", "")
        scan_start = info.get("scan_start")
        scan_date = (
            datetime.fromtimestamp(scan_start) if scan_start else None
        )

        metadata = {
            "scan_name": scan_name,
            "scanner_name": scanner_name,
            "policy_name": policy_name,
            "scan_date": scan_date,
            "source_file": f"API: {self.base_url}/scans/{scan_id}",
            "file_type": "nessus",
            "total_hosts": len(hosts),
            "total_vulns": 0,
        }

        if not hosts:
            return {"metadata": metadata, "vulnerabilities": _build_safe_dataframe([])}

        # 2. Duyệt từng host → lấy chi tiết lỗ hổng
        all_vulns = []
        total_hosts = len(hosts)

        for idx, host_info in enumerate(hosts):
            if not isinstance(host_info, dict):
                continue
            host_id = host_info.get("host_id")
            host_ip = host_info.get("hostname", "unknown")

            if progress_callback:
                progress_callback(
                    idx + 1, total_hosts,
                    f"Đang tải host {idx+1}/{total_hosts}: {host_ip}..."
                )

            try:
                host_data = self.get_host_details(scan_id, host_id)
            except Exception as e:
                if progress_callback:
                    progress_callback(
                        idx + 1, total_hosts,
                        f"⚠️ Lỗi khi tải host {host_ip}: {e}"
                    )
                continue

            if not isinstance(host_data, dict):
                host_data = {}

            host_vulns = host_data.get("vulnerabilities", [])
            if not isinstance(host_vulns, list):
                host_vulns = []

            host_info_data = host_data.get("info", {}) if isinstance(host_data.get("info"), dict) else {}
            host_fqdn = host_info_data.get("host-fqdn", "")
            host_actual_ip = host_info_data.get("host-ip", host_ip)

            for vuln in host_vulns:
                if not isinstance(vuln, dict):
                    continue

                try:
                    severity = int(vuln.get("severity", 0) or 0)
                except (ValueError, TypeError):
                    severity = 0

                # Bỏ qua Info nếu không include
                if not include_info and severity == 0:
                    continue

                try:
                    plugin_id = int(vuln.get("plugin_id", 0) or 0)
                except (ValueError, TypeError):
                    plugin_id = 0

                plugin_name = vuln.get("plugin_name", "") or ""
                plugin_family = vuln.get("plugin_family", "") or ""
                count = vuln.get("count", 1) or 1

                # Lấy chi tiết plugin output cho từng lỗ hổng
                plugin_output = ""
                synopsis = ""
                description = ""
                solution = ""
                see_also = ""
                cve_list = ""
                cvss_base = None
                cvss3_base = None
                exploit_available = False
                exploitability_ease = ""
                vuln_pub_date = None
                patch_pub_date = None
                port = 0
                protocol = ""
                svc_name = ""

                try:
                    plugin_data = self.get_plugin_output(scan_id, host_id, plugin_id)
                    if not isinstance(plugin_data, dict):
                        plugin_data = {}

                    p_info = plugin_data.get("info", {}) if isinstance(plugin_data.get("info"), dict) else {}
                    p_desc = p_info.get("plugindescription", {}) if isinstance(p_info.get("plugindescription"), dict) else {}
                    p_attrs = p_desc.get("pluginattributes", {}) if isinstance(p_desc.get("pluginattributes"), dict) else {}

                    synopsis = p_attrs.get("synopsis", "") or ""
                    description = p_attrs.get("description", "") or ""
                    solution = p_attrs.get("solution", "") or ""
                    see_also = p_attrs.get("see_also", "") or ""

                    # Risk information
                    risk_info = p_attrs.get("risk_information", {}) if isinstance(p_attrs.get("risk_information"), dict) else {}
                    cvss_base = _safe_float(risk_info.get("cvss_base_score"))
                    cvss3_base = _safe_float(risk_info.get("cvss3_base_score"))

                    # Exploit info
                    exploit_info = p_attrs.get("exploit_information", {}) if isinstance(p_attrs.get("exploit_information"), dict) else {}
                    exploit_available = bool(exploit_info.get("exploitability_ease", "")) or (str(exploit_info.get("exploit_available", "")).lower() == "true")
                    exploitability_ease = exploit_info.get("exploitability_ease", "") or ""

                    # CVE list
                    ref_info = p_attrs.get("ref_information", {}) if isinstance(p_attrs.get("ref_information"), dict) else {}
                    refs = ref_info.get("ref", [])
                    if isinstance(refs, dict):
                        refs = [refs]
                    elif not isinstance(refs, list):
                        refs = []
                    cves = [r.get("value", "") for r in refs if isinstance(r, dict) and r.get("name") == "cve"]
                    cve_list = ", ".join([str(c) for c in cves if c])

                    # Dates
                    vuln_info = p_attrs.get("vuln_information", {}) if isinstance(p_attrs.get("vuln_information"), dict) else {}
                    vuln_pub_date = vuln_info.get("vuln_publication_date")
                    patch_pub_date = vuln_info.get("patch_publication_date")

                    # Plugin outputs (có thể nhiều port)
                    outputs = plugin_data.get("outputs", [])
                    if not isinstance(outputs, list):
                        outputs = []
                    output_texts = []
                    for out in outputs:
                        if not isinstance(out, dict):
                            continue
                        ports_data = out.get("ports", {})
                        p_output = out.get("plugin_output", "") or ""
                        if p_output:
                            output_texts.append(p_output)

                        # Lấy port từ output
                        if isinstance(ports_data, dict):
                            for port_str in ports_data:
                                parts = [p.strip() for p in str(port_str).split("/")]
                                if len(parts) >= 1:
                                    port = _safe_int(parts[0]) or 0
                                if len(parts) >= 2:
                                    protocol = parts[1]
                                if len(parts) >= 3:
                                    svc_name = parts[2]

                    plugin_output = "\n---\n".join(output_texts)

                except Exception:
                    # Nếu không lấy được chi tiết, vẫn lưu thông tin cơ bản
                    pass

                vuln_record = {
                    "host_ip": host_actual_ip,
                    "host_name": host_fqdn or host_ip,
                    "port": port,
                    "protocol": protocol,
                    "service_name": svc_name,
                    "plugin_id": plugin_id,
                    "plugin_name": plugin_name,
                    "plugin_family": plugin_family,
                    "severity": severity,
                    "severity_label": SEVERITY_MAP.get(severity, "Info"),
                    "cvss_base_score": cvss_base,
                    "cvss3_base_score": cvss3_base,
                    "cve_list": cve_list,
                    "synopsis": synopsis,
                    "description": description,
                    "solution": solution,
                    "plugin_output": plugin_output[:8000],  # Giới hạn kích thước
                    "see_also": see_also,
                    "exploit_available": exploit_available,
                    "exploitability_ease": exploitability_ease,
                    "patch_pub_date": patch_pub_date,
                    "vuln_pub_date": vuln_pub_date,
                }
                all_vulns.append(vuln_record)

        df = _build_safe_dataframe(all_vulns)
        metadata["total_vulns"] = len(all_vulns)

        return {"metadata": metadata, "vulnerabilities": df}


# ═════════════════════════════════════════════════════════════
#  HELPERS
# ═════════════════════════════════════════════════════════════

def _timestamp_to_str(ts) -> str:
    """Chuyển Unix timestamp sang chuỗi datetime."""
    if ts:
        try:
            return datetime.fromtimestamp(int(ts)).strftime("%Y-%m-%d %H:%M:%S")
        except (ValueError, TypeError, OSError):
            pass
    return ""


def _safe_float(value) -> Optional[float]:
    """Chuyển sang float an toàn."""
    try:
        return float(value) if value else None
    except (ValueError, TypeError):
        return None


def _safe_int(value) -> Optional[int]:
    """Chuyển sang int an toàn."""
    try:
        return int(value) if value else None
    except (ValueError, TypeError):
        return None
