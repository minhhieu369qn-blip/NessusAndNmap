"""
sample_lab_data.py - Bộ dữ liệu thực nghiệm chuẩn bám sát 4 kịch bản của Đề án Phương án A
và dữ liệu Bằng chứng Pháp chứng số (Wireshark SMB2 & Windows Event Log 4624/4672).

Hạ tầng Lab:
  - Host Scanner : 192.168.104.1   (Windows 11 Host - Nessus Engine + AI Dashboard)
  - Target VM    : 192.168.104.129 (Windows 11 Pro Build 26200)
  - Secondary VM : 192.168.104.132 (Kali Linux / Ubuntu)
  - NAT Gateway  : 192.168.104.254 (VMware VMnet8 192.168.104.0/24)
"""

from datetime import datetime
import pandas as pd


def get_lab_topology_nodes() -> pd.DataFrame:
    """Trả về danh sách 4 node mạng trong Kịch bản 1: Trinh sát mạng (Host Discovery)."""
    return pd.DataFrame([
        {
            "IP Address": "192.168.104.1",
            "Hostname": "WIN11-SCANNER-HOST",
            "OS / Platform": "Windows 11 Host",
            "Vai trò": "Host Machine (Nessus Scanner :8834, Wireshark, AI Web Dashboard)",
            "Trạng thái": "🟢 Online (Scanner)",
            "Open Ports": "8834/tcp (Nessus), 8501/tcp (AI Dashboard), 1433/tcp (SQL Server)",
        },
        {
            "IP Address": "192.168.104.129",
            "Hostname": "WIN11-TARGET-PRO",
            "OS / Platform": "Windows 11 Pro Build 26200",
            "Vai trò": "Target VM (Máy mục tiêu chứa VLC 2.2.0, CVE-2013-3900, ICMP, SMB)",
            "Trạng thái": "🔴 Online (Target)",
            "Open Ports": "135/tcp (RPC), 139/tcp (NetBIOS), 445/tcp (SMB2), 3389/tcp (RDP), ICMP",
        },
        {
            "IP Address": "192.168.104.132",
            "Hostname": "KALI-PENTEST-VM",
            "OS / Platform": "Kali Linux 2026 / Ubuntu",
            "Vai trò": "Secondary VM (Máy kiểm thử mở rộng / Đối chứng tấn công)",
            "Trạng thái": "🟡 Online (Secondary)",
            "Open Ports": "22/tcp (SSH), 80/tcp (HTTP)",
        },
        {
            "IP Address": "192.168.104.254",
            "Hostname": "VMNET8-NAT-GW",
            "OS / Platform": "VMware Virtual Router / DHCP",
            "Vai trò": "Virtual Gateway & NAT (Subnet 192.168.104.0/24)",
            "Trạng thái": "🔵 Online (Gateway)",
            "Open Ports": "53/udp (DNS), 67/udp (DHCP)",
        },
    ])


def _make_info_records(target_ip: str = "192.168.104.129", count: int = 43) -> list[dict]:
    """Sinh danh sách các plugin Info (Severity = 0) chuẩn của Nessus Credentialed Scan."""
    base_infos = [
        (19506, "Nessus Scan Information", "Settings", 0, "tcp", "general", "Thông tin chi tiết phiên quét Nessus (Credentialed checks: yes, SMB login: Administrator)."),
        (10394, "Microsoft Windows SMB LogIn Possible", "Windows", 445, "tcp", "cifs", "Đăng nhập thành công vào dịch vụ SMB2 bằng tài khoản quản trị nội bộ (Logon Type 3)."),
        (10400, "Microsoft Windows SMB Registry Remotely Accessible", "Windows", 445, "tcp", "cifs", "Dịch vụ Remote Registry cho phép Nessus truy vấn nhánh HKLM để kiểm tra bản vá và phần mềm."),
        (20811, "Microsoft Windows Installed Software Enumeration (credentialed check)", "Windows", 445, "tcp", "cifs", "Liệt kê danh sách phần mềm đã cài đặt trên máy mục tiêu thông qua Registry."),
        (11936, "OS Identification", "General", 0, "tcp", "general", "Hệ điều hành nhận diện: Microsoft Windows 11 Pro Build 26200 (64-bit)."),
        (10785, "Microsoft Windows SMB NativeLanManager Remote System Information Disclosure", "Windows", 445, "tcp", "cifs", "Thu thập phiên bản SMB và tên miền/Workgroup từ gói bắt tay NTLMSSP."),
        (24272, "Netstat Portscanner (WMI)", "Port scanners", 445, "tcp", "cifs", "Liệt kê các cổng đang lắng nghe (135, 139, 445, 3389) từ bên trong hệ điều hành qua WMI."),
        (35716, "Ethernet Card Manufacturer Detection", "General", 0, "tcp", "general", "MAC OUI: 00:0C:29 (VMware, Inc. Virtual Network Interface)."),
    ]
    records = []
    for i in range(count):
        if i < len(base_infos):
            pid, pname, pfam, port, proto, svc, out = base_infos[i]
        else:
            pid = 50000 + i
            pname = f"Windows System & Registry Audit Check #{i - len(base_infos) + 1}"
            pfam = "Windows"
            port = 445
            proto = "tcp"
            svc = "cifs"
            out = f"Credentialed Registry/WMI verification check #{i + 1} completed on {target_ip}."
        records.append({
            "host_ip": target_ip,
            "host_name": "WIN11-TARGET-PRO",
            "os": "Microsoft Windows 11 Pro Build 26200",
            "port": port,
            "protocol": proto,
            "service_name": svc,
            "plugin_id": pid,
            "plugin_name": pname,
            "plugin_family": pfam,
            "severity": 0,
            "severity_label": "Info",
            "cvss_base_score": None,
            "cvss3_base_score": None,
            "cve_list": "",
            "synopsis": pname,
            "description": out,
            "solution": "Không yêu cầu khắc phục (Thông tin hệ thống).",
            "plugin_output": out,
            "see_also": "",
            "exploit_available": False,
        })
    return records


def get_scenario_datasets() -> list[dict]:
    """
    Trả về 4 phiên quét thực nghiệm chuẩn của Phương án A:
      1. Kịch bản 1: Host Discovery (192.168.104.0/24)
      2. Kịch bản 2: Quét Black-Box (Uncredentialed - 192.168.104.129)
      3. Kịch bản 3: Quét White-Box (Credentialed SMB/Registry - 192.168.104.129) -> 47 mục
      4. Kịch bản 4: Quét Kiểm chứng sau khi chạy Script AI (Validation Re-scan) -> 0 lỗi
    """
    target_ip = "192.168.104.129"

    # ── 2 lỗi Medium phát hiện được từ bên ngoài mạng (Black-Box) ──
    vuln_smb_signing = {
        "host_ip": target_ip,
        "host_name": "WIN11-TARGET-PRO",
        "os": "Microsoft Windows 11 Pro Build 26200",
        "port": 445,
        "protocol": "tcp",
        "service_name": "cifs",
        "plugin_id": 57608,
        "plugin_name": "SMB Signing not required",
        "plugin_family": "Misc.",
        "severity": 2,
        "severity_label": "Medium",
        "cvss_base_score": 5.0,
        "cvss3_base_score": 5.3,
        "cve_list": "CVE-2016-2110",
        "synopsis": "Signing is not required on the remote SMB server.",
        "description": (
            "Dịch vụ SMB2 trên máy mục tiêu (192.168.104.129) không bắt buộc ký số gói tin (Message Signing). "
            "Kẻ tấn công chưa xác thực nằm trong cùng dải mạng 192.168.104.0/24 có thể thực hiện tấn công "
            "Man-in-the-Middle (MitM) hoặc SMB Relay để chiếm phiên đăng nhập."
        ),
        "solution": (
            "Bật chính sách 'Microsoft network server: Digitally sign communications (always)' trong Group Policy "
            "hoặc thiết lập Registry RequireSecuritySignature = 1 tại nhánh LanmanServer\\Parameters."
        ),
        "plugin_output": "Signing is enabled on the remote SMB server, but it is not required.",
        "see_also": "https://learn.microsoft.com/en-us/windows/security/threat-protection/security-policy-settings/microsoft-network-server-digitally-sign-communications-always",
        "exploit_available": False,
    }

    vuln_icmp_timestamp = {
        "host_ip": target_ip,
        "host_name": "WIN11-TARGET-PRO",
        "os": "Microsoft Windows 11 Pro Build 26200",
        "port": 0,
        "protocol": "icmp",
        "service_name": "icmp",
        "plugin_id": 10114,
        "plugin_name": "ICMP Timestamp Request Remote Date Disclosure",
        "plugin_family": "General",
        "severity": 2,
        "severity_label": "Medium",
        "cvss_base_score": 2.1,
        "cvss3_base_score": 4.3,
        "cve_list": "CVE-1999-0524",
        "synopsis": "It is possible to determine the exact time set on the remote host.",
        "description": (
            "Máy mục tiêu phản hồi các gói tin ICMP_TIMESTAMP (Type 13) bằng gói trả lời ICMP Timestamp Reply (Type 14). "
            "Thông tin đồng hồ hệ thống chính xác có thể bị kẻ tấn công lợi dụng để phá các cơ chế sinh số ngẫu nhiên "
            "dựa trên thời gian hoặc hỗ trợ tấn công đồng bộ phiên."
        ),
        "solution": (
            "Cấu hình Windows Defender Firewall chặn gói tin ICMPv4 Type 13 (Inbound Timestamp Request) "
            "và Type 14 (Outbound Timestamp Reply)."
        ),
        "plugin_output": "The difference between the local and remote clocks is 0 seconds (ICMP Type 13/14 enabled).",
        "see_also": "https://www.cve.org/CVERecord?id=CVE-1999-0524",
        "exploit_available": False,
    }

    # ── 2 lỗi Critical & High chỉ phát hiện được khi quét White-Box (Credentialed SMB/Registry) ──
    vuln_vlc_critical = {
        "host_ip": target_ip,
        "host_name": "WIN11-TARGET-PRO",
        "os": "Microsoft Windows 11 Pro Build 26200",
        "port": 445,
        "protocol": "tcp",
        "service_name": "cifs",
        "plugin_id": 81817,
        "plugin_name": "VLC Media Player 2.2.0 Multiple Remote Code Execution Vulnerabilities",
        "plugin_family": "Windows",
        "severity": 4,
        "severity_label": "Critical",
        "cvss_base_score": 9.3,
        "cvss3_base_score": 9.8,
        "cve_list": "CVE-2018-11529, CVE-2017-8311, CVE-2016-5108",
        "synopsis": "A media player installed on the remote Windows host is affected by multiple RCE vulnerabilities.",
        "description": (
            "Thông qua xác thực SMB và kiểm tra Registry/Filesystem nội bộ, Nessus phát hiện phần mềm "
            "VLC Media Player phiên bản 2.2.0 (Weatherwax) đang được cài đặt trên máy 192.168.104.129. "
            "Phiên bản này chứa nhiều lỗ hổng tràn bộ đệm (Heap-based Buffer Overflow & Use-After-Free) "
            "khi xử lý tệp đa phương tiện MKV/MP4 độc hại, cho phép kẻ tấn công thực thi mã từ xa (RCE) với quyền người dùng."
        ),
        "solution": (
            "Gỡ bỏ hoàn toàn VLC phiên bản cũ 2.2.0 và dọn sạch thư mục cài đặt tại C:\\Program Files\\VideoLAN\\VLC "
            "(hoặc nâng cấp lên phiên bản VLC mới nhất >= 3.0.21)."
        ),
        "plugin_output": (
            "  Path              : C:\\Program Files\\VideoLAN\\VLC\\vlc.exe\n"
            "  Installed version : 2.2.0.0\n"
            "  Fixed version     : 3.0.21"
        ),
        "see_also": "https://www.videolan.org/security/",
        "exploit_available": True,
    }

    vuln_winverifytrust_high = {
        "host_ip": target_ip,
        "host_name": "WIN11-TARGET-PRO",
        "os": "Microsoft Windows 11 Pro Build 26200",
        "port": 445,
        "protocol": "tcp",
        "service_name": "cifs",
        "plugin_id": 166555,
        "plugin_name": "WinVerifyTrust Signature Validation Vulnerability (CVE-2013-3900)",
        "plugin_family": "Windows",
        "severity": 3,
        "severity_label": "High",
        "cvss_base_score": 7.6,
        "cvss3_base_score": 8.8,
        "cve_list": "CVE-2013-3900",
        "synopsis": "The remote Windows host is missing the EnableCertPaddingCheck registry mitigation.",
        "description": (
            "Hàm WinVerifyTrust trong Microsoft Windows không kiểm tra chặt chẽ phần đệm (Certificate Padding) "
            "trong cấu trúc chữ ký số Authenticode của tệp thực thi PE. Kẻ tấn công có thể chèn mã độc vào phần cuối "
            "của một file thực thi hợp pháp đã được ký số mà không làm mất hiệu lực chữ ký số đó."
        ),
        "solution": (
            "Tạo khóa Registry DWORD 'EnableCertPaddingCheck' = 1 tại cả 2 nhánh:\n"
            "1. HKLM\\Software\\Microsoft\\Cryptography\\Wintrust\\Config\n"
            "2. HKLM\\Software\\Wow6432Node\\Microsoft\\Cryptography\\Wintrust\\Config"
        ),
        "plugin_output": (
            "Registry Key HKLM\\Software\\Microsoft\\Cryptography\\Wintrust\\Config\\EnableCertPaddingCheck is not set or equals 0.\n"
            "Registry Key HKLM\\Software\\Wow6432Node\\Microsoft\\Cryptography\\Wintrust\\Config\\EnableCertPaddingCheck is not set."
        ),
        "see_also": "https://msrc.microsoft.com/update-guide/vulnerability/CVE-2013-3900",
        "exploit_available": True,
    }

    # 1. Kịch bản 1: Host Discovery (4 hosts)
    kb1_records = []
    for ip, hname in [
        ("192.168.104.1", "WIN11-SCANNER-HOST"),
        ("192.168.104.129", "WIN11-TARGET-PRO"),
        ("192.168.104.132", "KALI-PENTEST-VM"),
        ("192.168.104.254", "VMNET8-NAT-GW"),
    ]:
        kb1_records.append({
            "host_ip": ip,
            "host_name": hname,
            "os": "Network Node",
            "port": 0,
            "protocol": "icmp",
            "service_name": "general",
            "plugin_id": 10180,
            "plugin_name": "Ping the remote host",
            "plugin_family": "Port scanners",
            "severity": 0,
            "severity_label": "Info",
            "cvss_base_score": None,
            "cvss3_base_score": None,
            "cve_list": "",
            "synopsis": "The remote host is up and responding to ARP/ICMP discovery.",
            "description": f"Host {ip} ({hname}) is alive on subnet 192.168.104.0/24.",
            "solution": "N/A",
            "plugin_output": f"RTT = 0.8 ms (ARP / ICMP Echo Reply from {ip})",
            "see_also": "",
            "exploit_available": False,
        })

    # 2. Kịch bản 2: Black-Box Scan (2 Medium)
    kb2_records = [vuln_smb_signing, vuln_icmp_timestamp]

    # 3. Kịch bản 3: White-Box Scan (47 mục: 1 Critical, 1 High, 2 Medium, 43 Info)
    kb3_records = [vuln_vlc_critical, vuln_winverifytrust_high, vuln_smb_signing, vuln_icmp_timestamp] + _make_info_records(target_ip, 43)

    # 4. Kịch bản 4: Validation Re-scan (Sau khi chạy PowerShell Auto-Remediation -> 0 lỗi)
    kb4_records = _make_info_records(target_ip, 41)

    now = datetime.now()
    return [
        {
            "scan_name": "[Kịch bản 1] Trinh sát mạng Host Discovery (192.168.104.0/24)",
            "source_file": "KB1_Host_Discovery.nessus",
            "file_type": "nessus",
            "scan_date": now,
            "scanner_name": "Nessus Essentials (192.168.104.1)",
            "policy_name": "Host Discovery",
            "total_hosts": 4,
            "total_vulns": len(kb1_records),
            "notes": "Phát hiện 4 máy sống trong dải mạng NAT VMnet8 192.168.104.0/24",
            "df": pd.DataFrame(kb1_records),
        },
        {
            "scan_name": "[Kịch bản 2] Quét Black-Box Không xác thực (192.168.104.129)",
            "source_file": "KB2_BlackBox_Uncredentialed.nessus",
            "file_type": "nessus",
            "scan_date": now,
            "scanner_name": "Nessus Essentials (192.168.104.1)",
            "policy_name": "Basic Network Scan (Uncredentialed)",
            "total_hosts": 1,
            "total_vulns": len(kb2_records),
            "notes": "Quét từ bên ngoài không cung cấp tài khoản SMB: chỉ thấy 2 lỗi Medium (SMB Signing, ICMP Timestamp)",
            "df": pd.DataFrame(kb2_records),
        },
        {
            "scan_name": "[Kịch bản 3] Quét White-Box Có xác thực SMB/Registry (192.168.104.129)",
            "source_file": "KB3_WhiteBox_Credentialed.nessus",
            "file_type": "nessus",
            "scan_date": now,
            "scanner_name": "Nessus Essentials (192.168.104.1)",
            "policy_name": "Credentialed Patch Audit (White-Box)",
            "total_hosts": 1,
            "total_vulns": len(kb3_records),
            "notes": "Quét có xác thực SMB/Registry: Phát hiện 47 mục, có Critical 9.8 (VLC 2.2.0) và High 8.8 (WinVerifyTrust CVE-2013-3900)",
            "df": pd.DataFrame(kb3_records),
        },
        {
            "scan_name": "[Kịch bản 4] Quét Kiểm chứng sau Auto-Remediation (Validation Scan)",
            "source_file": "KB4_Validation_After_Patch.nessus",
            "file_type": "nessus",
            "scan_date": now,
            "scanner_name": "Nessus Essentials (192.168.104.1)",
            "policy_name": "Credentialed Patch Audit (Validation)",
            "total_hosts": 1,
            "total_vulns": len(kb4_records),
            "notes": "Quét lại sau khi chạy kịch bản PowerShell của AI: Lỗ hổng Critical, High, Medium biến mất hoàn toàn (100% Fixed)",
            "df": pd.DataFrame(kb4_records),
        },
    ]


def get_sample_wireshark_packets() -> pd.DataFrame:
    """Dữ liệu gói tin Wireshark mẫu minh họa quá trình bắt tay SMB2 & NTLMSSP_AUTH khi quét White-Box."""
    return pd.DataFrame([
        {
            "No.": 142,
            "Time (s)": "1.204112",
            "Source": "192.168.104.1",
            "Destination": "192.168.104.129",
            "Protocol": "TCP",
            "Port": "54312 -> 445",
            "Info": "[SYN] Seq=0 Win=64240 Len=0 MSS=1460 (Khởi tạo kết nối TCP tới cổng SMB 445)",
        },
        {
            "No.": 145,
            "Time (s)": "1.205890",
            "Source": "192.168.104.1",
            "Destination": "192.168.104.129",
            "Protocol": "SMB2",
            "Port": "54312 -> 445",
            "Info": "Negotiate Protocol Request (Dialect: SMB 2.1, SMB 3.0.2, SMB 3.1.1)",
        },
        {
            "No.": 146,
            "Time (s)": "1.207104",
            "Source": "192.168.104.129",
            "Destination": "192.168.104.1",
            "Protocol": "SMB2",
            "Port": "445 -> 54312",
            "Info": "Negotiate Protocol Response (Security Mode: Signing Enabled, Not Required -> Plugin 57608)",
        },
        {
            "No.": 147,
            "Time (s)": "1.209451",
            "Source": "192.168.104.1",
            "Destination": "192.168.104.129",
            "Protocol": "SMB2",
            "Port": "54312 -> 445",
            "Info": "Session Setup Request, NTLMSSP_NEGOTIATE",
        },
        {
            "No.": 148,
            "Time (s)": "1.211022",
            "Source": "192.168.104.129",
            "Destination": "192.168.104.1",
            "Protocol": "SMB2",
            "Port": "445 -> 54312",
            "Info": "Session Setup Response, Error: STATUS_MORE_PROCESSING_REQUIRED, NTLMSSP_CHALLENGE",
        },
        {
            "No.": 149,
            "Time (s)": "1.214310",
            "Source": "192.168.104.1",
            "Destination": "192.168.104.129",
            "Protocol": "SMB2",
            "Port": "54312 -> 445",
            "Info": "Session Setup Request, NTLMSSP_AUTH, User: WIN11-TARGET-PRO\\Administrator",
        },
        {
            "No.": 150,
            "Time (s)": "1.218990",
            "Source": "192.168.104.129",
            "Destination": "192.168.104.1",
            "Protocol": "SMB2",
            "Port": "445 -> 54312",
            "Info": "Session Setup Response (STATUS_SUCCESS - Đăng nhập White-Box thành công)",
        },
        {
            "No.": 154,
            "Time (s)": "1.224115",
            "Source": "192.168.104.1",
            "Destination": "192.168.104.129",
            "Protocol": "SMB2",
            "Port": "54312 -> 445",
            "Info": "Tree Connect Request Tree: \\\\192.168.104.129\\IPC$ & \\\\192.168.104.129\\ADMIN$",
        },
        {
            "No.": 168,
            "Time (s)": "1.249812",
            "Source": "192.168.104.1",
            "Destination": "192.168.104.129",
            "Protocol": "WINREG",
            "Port": "54312 -> 445",
            "Info": "OpenKey Request: HKLM\\Software\\Microsoft\\Cryptography\\Wintrust\\Config (Kiểm tra CVE-2013-3900)",
        },
        {
            "No.": 189,
            "Time (s)": "1.298104",
            "Source": "192.168.104.1",
            "Destination": "192.168.104.129",
            "Protocol": "SMB2",
            "Port": "54312 -> 445",
            "Info": "Create Request File: Program Files\\VideoLAN\\VLC\\vlc.exe (Kiểm tra version VLC 2.2.0 -> Critical 9.8)",
        },
    ])


def get_sample_windows_event_logs() -> pd.DataFrame:
    """Dữ liệu nhật ký Windows Security Event Log mẫu trên máy 192.168.104.129 khi Nessus quét."""
    return pd.DataFrame([
        {
            "Event ID": 4624,
            "Time Created": "2026-11-10 22:15:04",
            "Level": "Information (Audit Success)",
            "Task Category": "Logon",
            "Logon Type": "3 (Network Logon - SMB)",
            "Account Name": "Administrator",
            "Source Network Address": "192.168.104.1 (Scanner Host)",
            "Authentication Package": "NTLM (NTLMv2)",
            "Mô tả Pháp chứng": "Xác nhận Nessus Scanner (192.168.104.1) đăng nhập thành công qua mạng (Type 3) vào máy mục tiêu.",
        },
        {
            "Event ID": 4672,
            "Time Created": "2026-11-10 22:15:04",
            "Level": "Information (Audit Success)",
            "Task Category": "Special Logon",
            "Logon Type": "3 (Admin Privileges)",
            "Account Name": "Administrator",
            "Source Network Address": "192.168.104.1 (Scanner Host)",
            "Authentication Package": "SeSecurityPrivilege, SeBackupPrivilege, SeDebugPrivilege",
            "Mô tả Pháp chứng": "Cấp đặc quyền quản trị cao nhất cho phiên SMB để đọc toàn bộ Registry (HKLM) và thư mục hệ thống.",
        },
        {
            "Event ID": 5140,
            "Time Created": "2026-11-10 22:15:05",
            "Level": "Information (Audit Success)",
            "Task Category": "File Share",
            "Logon Type": "3 (SMB Share Access)",
            "Account Name": "Administrator",
            "Source Network Address": "192.168.104.1 (Scanner Host)",
            "Authentication Package": "Share Name: \\\\*\\IPC$ & \\\\*\\ADMIN$",
            "Mô tả Pháp chứng": "Nessus truy cập chia sẻ quản trị ẩn IPC$ và ADMIN$ để gọi RPC/WINREG kiểm tra lỗ hổng nội bộ.",
        },
        {
            "Event ID": 4634,
            "Time Created": "2026-11-10 22:17:42",
            "Level": "Information (Audit Success)",
            "Task Category": "Logoff",
            "Logon Type": "3 (Network Logoff)",
            "Account Name": "Administrator",
            "Source Network Address": "192.168.104.1 (Scanner Host)",
            "Authentication Package": "SMB Session Closed",
            "Mô tả Pháp chứng": "Nessus đóng phiên đăng nhập mạng an toàn sau khi hoàn tất thu thập 47 mục dữ liệu.",
        },
    ])
