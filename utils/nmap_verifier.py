"""
utils/nmap_verifier.py - Engine Quét Mạng, Phân tích Bề mặt Tấn công & Kiểm chứng Phòng thủ bằng Nmap / Nping.

Cách hoạt động:
  1. Trước khi quét: Giao diện hoàn toàn trung lập, người dùng nhập mục tiêu bất kỳ và chọn hồ sơ quét.
  2. Sau khi quét: Hệ thống đọc kết quả XML / Output thực tế từ Nmap & Nping để:
     - Tự động đánh giá các tiêu chí an ninh: Phân định rõ ràng PASS ✅ (Đã phòng thủ an toàn),
       FAIL ❌ (Phát hiện lỗ hổng / cấu hình yếu có thể bị tấn công), WARN ⚠️ (Cổng dịch vụ phơi lộ).
     - Giải thích kịch bản tấn công (Attack Scenario) dựa trên đúng bằng chứng thu được.
     - Đưa ra khuyến nghị và câu lệnh PowerShell / Firewall cụ thể để phòng thủ.
     - Cho phép đối chiếu 2 lần quét (Trước phòng thủ vs. Sau phòng thủ) để chứng minh hiệu quả.
"""

from __future__ import annotations

import os
import re
import shlex
import shutil
import subprocess
import tempfile
import xml.etree.ElementTree as ET
from datetime import datetime
from pathlib import Path

DEFAULT_NMAP_DIRS = [
    Path(r"C:\Program Files (x86)\Nmap"),
    Path(r"C:\Program Files\Nmap"),
]

# Các hồ sơ quét chuẩn của Nmap kết hợp các hồ sơ Kiểm định An ninh (Security Audit Profiles)
SCAN_PROFILES: dict[str, dict] = {
    "Kiểm định An ninh SMB & Ký số (Port 445 – smb2-security-mode, smb-protocols)": {
        "args": ["-p", "445", "-sV", "--script", "smb2-security-mode,smb-protocols"],
        "uses_ports": False,
        "admin": False,
        "desc": "Kiểm tra cấu hình bắt buộc chữ ký số SMB (chống MITM / SMB Relay) và kiểm tra giao thức SMBv1/v2/v3 trên cổng 445.",
    },
    "Kiểm định Bề mặt Tấn công Dịch vụ Windows (Port 135, 139, 445, 3389)": {
        "args": ["-p", "135,139,445,3389", "-sV", "--script", "smb2-security-mode,smb-protocols,rdp-enum-encryption"],
        "uses_ports": False,
        "admin": False,
        "desc": "Quét các cổng dịch vụ trọng yếu của Windows (RPC, NetBIOS, SMB, RDP) và đánh giá cấu hình bảo mật.",
    },
    "Dò tìm Lỗ hổng Đã biết bằng NSE (--script vuln)": {
        "args": ["-sV", "--script", "vuln"],
        "uses_ports": True,
        "admin": False,
        "desc": "Chạy bộ script 'vuln' của Nmap để dò các lỗ hổng CVE đã biết trên các cổng mở.",
    },
    "Phát hiện Dịch vụ & Script Mặc định (-sV -sC)": {
        "args": ["-sV", "-sC"],
        "uses_ports": True,
        "admin": False,
        "desc": "Xác định phiên bản phần mềm dịch vụ (-sV) kết hợp chạy nhóm script kiểm tra mặc định (-sC).",
    },
    "Quét nhanh 100 cổng phổ biến (-F)": {
        "args": ["-F"],
        "uses_ports": False,
        "admin": False,
        "desc": "Quét nhanh 100 cổng TCP phổ biến nhất để khảo sát bề mặt tấn công.",
    },
    "Quét cổng TCP (tự chọn cổng)": {
        "args": [],
        "uses_ports": True,
        "admin": False,
        "desc": "Quét các cổng bạn nhập ở ô 'Cổng'. Bỏ trống = 1000 cổng mặc định.",
    },
    "Phát hiện dịch vụ & phiên bản (-sV)": {
        "args": ["-sV"],
        "uses_ports": True,
        "admin": False,
        "desc": "Xác định tên dịch vụ và phiên bản phần mềm trên các cổng mở (-sV).",
    },
    "Ping scan – phát hiện host đang hoạt động (-sn)": {
        "args": ["-sn"],
        "uses_ports": False,
        "admin": False,
        "desc": "Chỉ kiểm tra host nào đang bật (-sn), không quét cổng.",
    },
    "Nhận diện hệ điều hành (-O)": {
        "args": ["-O"],
        "uses_ports": True,
        "admin": True,
        "desc": "Đoán hệ điều hành dựa trên dấu vân tay TCP/IP (-O). Cần quyền Administrator.",
    },
    "Quét toàn diện (-A)": {
        "args": ["-A"],
        "uses_ports": True,
        "admin": True,
        "desc": "Kết hợp -sV, -O, script mặc định và traceroute.",
    },
    "Chỉ chạy NSE script tự chọn": {
        "args": [],
        "uses_ports": True,
        "admin": False,
        "desc": "Chỉ chạy các script bạn chọn ở mục 'Tùy chọn nâng cao -> NSE script'.",
    },
}

TIMING_TEMPLATES = {
    "T0 – Paranoid": "-T0",
    "T1 – Sneaky": "-T1",
    "T2 – Polite": "-T2",
    "T3 – Normal (mặc định)": "-T3",
    "T4 – Aggressive": "-T4",
    "T5 – Insane": "-T5",
}

_BLOCKED_ARG_PREFIXES = ("-oN", "-oX", "-oG", "-oA", "-oS", "-oM", "--resume", "--stylesheet", "-iL")
_TARGET_RE = re.compile(r"^[A-Za-z0-9\.\-:/,_\*]+$")


# Cơ sở tri thức phân tích rủi ro cho các cổng dịch vụ phổ biến khi Nmap phát hiện mở (OPEN)
PORT_SECURITY_KNOWLEDGE: dict[int, dict] = {
    21: {
        "name": "FTP (File Transfer Protocol)",
        "severity": "High",
        "attack": "Truyền tài khoản và dữ liệu dạng rõ (cleartext). Kẻ tấn công có thể nghe lén (Sniffing), thử mật khẩu (Brute-force) hoặc đăng nhập Anonymous.",
        "defense": "Tắt dịch vụ FTP hoặc chuyển sang SFTP/FTPS; chặn cổng 21 trên tường lửa nếu không sử dụng.",
        "cmd": 'New-NetFirewallRule -DisplayName "Block_FTP_Port21" -Direction Inbound -LocalPort 21 -Protocol TCP -Action Block',
    },
    22: {
        "name": "SSH (Secure Shell)",
        "severity": "Low",
        "attack": "Kẻ tấn công có thể thực hiện dò mật khẩu tự động (SSH Brute-force) hoặc khai thác nếu phiên bản OpenSSH lỗi thời.",
        "defense": "Sử dụng xác thực bằng khóa công khai (SSH Key), tắt đăng nhập bằng mật khẩu và giới hạn IP được phép kết nối.",
        "cmd": 'New-NetFirewallRule -DisplayName "Restrict_SSH_Port22" -Direction Inbound -LocalPort 22 -Protocol TCP -Action Block',
    },
    23: {
        "name": "Telnet",
        "severity": "High",
        "attack": "Toàn bộ phiên điều khiển từ xa và mật khẩu truyền dạng văn bản thuần (Cleartext), cực kỳ dễ bị nghe lén MITM.",
        "defense": "Vô hiệu hóa hoàn toàn dịch vụ Telnet và thay thế bằng SSH.",
        "cmd": 'Stop-Service TlntSvr -Force -ErrorAction SilentlyContinue; New-NetFirewallRule -DisplayName "Block_Telnet_23" -Direction Inbound -LocalPort 23 -Protocol TCP -Action Block',
    },
    80: {
        "name": "HTTP Web Server",
        "severity": "Low",
        "attack": "Giao thức HTTP không mã hóa TLS; có thể bị tấn công xen giữa (MITM) hoặc rà quét lỗ hổng ứng dụng web (SQLi, XSS, Directory Traversal).",
        "defense": "Chuyển hướng bắt buộc sang HTTPS (TLS 1.2/1.3) và cập nhật bản vá cho Web Server.",
        "cmd": "# Cấu hình HTTPS Redirect trên IIS / Web Server của bạn",
    },
    135: {
        "name": "Microsoft Windows RPC (MSRPC)",
        "severity": "Medium",
        "attack": "Cổng 135 (Endpoint Mapper) cho phép kẻ tấn công liệt kê các dịch vụ DCOM/RPC nội bộ, phục vụ di chuyển ngang (Lateral Movement / WMIExec).",
        "defense": "Chỉ cho phép kết nối RPC từ các máy quản trị tin cậy; chặn cổng 135 từ các mạng không tin cậy qua Windows Firewall.",
        "cmd": 'New-NetFirewallRule -DisplayName "Block_MSRPC_135_Inbound" -Direction Inbound -LocalPort 135 -Protocol TCP -Action Block',
    },
    139: {
        "name": "NetBIOS Session Service",
        "severity": "Medium",
        "attack": "Dịch vụ chia sẻ phiên NetBIOS đời cũ; kẻ tấn công có thể liệt kê tên máy, nhóm làm việc (NetBIOS Enumeration) và hỗ trợ tấn công đầu độc tên miền nội bộ.",
        "defense": "Tắt NetBIOS over TCP/IP trong cấu hình card mạng và chặn cổng 139 trên tường lửa.",
        "cmd": 'New-NetFirewallRule -DisplayName "Block_NetBIOS_139_Inbound" -Direction Inbound -LocalPort 139 -Protocol TCP -Action Block',
    },
    445: {
        "name": "Microsoft-DS (SMB File Sharing)",
        "severity": "Medium",
        "attack": "Bề mặt tấn công chính trong mạng LAN Windows: NTLM/SMB Relay (MITM), Pass-the-Hash, PsExec, hoặc khai thác lỗ hổng dịch vụ SMB.",
        "defense": "Bắt buộc bật ký số SMB (RequireSecuritySignature = 1), vô hiệu hóa SMBv1 và giới hạn truy cập cổng 445.",
        "cmd": "Set-SmbServerConfiguration -RequireSecuritySignature $true -EnableSecuritySignature $true -Force",
    },
    1433: {
        "name": "Microsoft SQL Server",
        "severity": "Medium",
        "attack": "Phơi lộ trực tiếp cổng cơ sở dữ liệu ra mạng dễ dẫn tới tấn công dò mật khẩu tài khoản 'sa' hoặc khai thác xp_cmdshell.",
        "defense": "Giới hạn IP được phép kết nối tới cổng 1433 và tắt xác thực SQL trực tiếp nếu chỉ dùng nội bộ.",
        "cmd": 'New-NetFirewallRule -DisplayName "Restrict_SQL_1433" -Direction Inbound -LocalPort 1433 -Protocol TCP -Action Block',
    },
    3389: {
        "name": "Remote Desktop Protocol (RDP)",
        "severity": "Medium",
        "attack": "Dịch vụ điều khiển màn hình từ xa thường xuyên là mục tiêu của tấn công Brute-force mật khẩu, Man-in-the-Middle hoặc lỗ hổng kiểu BlueKeep.",
        "defense": "Bật bắt buộc Network Level Authentication (NLA), giới hạn IP truy cập cổng 3389 và bật mã hóa TLS cho RDP.",
        "cmd": 'Set-ItemProperty -Path "HKLM:\\System\\CurrentControlSet\\Control\\Terminal Server\\WinStations\\RDP-Tcp" -Name "UserAuthentication" -Value 1',
    },
}


# ─────────────────────────────────────────────────────────
#  MÔI TRƯỜNG
# ─────────────────────────────────────────────────────────

def detect_nmap_environment() -> dict:
    """Tìm nmap.exe, nping.exe và thư mục scripts NSE."""
    nmap_bin = shutil.which("nmap")
    nping_bin = shutil.which("nping")
    for d in DEFAULT_NMAP_DIRS:
        if not nmap_bin and (d / "nmap.exe").exists():
            nmap_bin = str(d / "nmap.exe")
        if not nping_bin and (d / "nping.exe").exists():
            nping_bin = str(d / "nping.exe")

    version = ""
    scripts_dir = ""
    if nmap_bin:
        try:
            proc = subprocess.run(
                [nmap_bin, "--version"], capture_output=True, text=True,
                timeout=8, encoding="utf-8", errors="replace",
            )
            lines = (proc.stdout or "").strip().splitlines()
            version = lines[0] if lines else ""
        except Exception as e:
            version = f"Không đọc được phiên bản: {e}"
        cand = Path(nmap_bin).parent / "scripts"
        if cand.exists():
            scripts_dir = str(cand)

    return {
        "available": bool(nmap_bin),
        "nmap_path": nmap_bin or "",
        "nping_path": nping_bin or "",
        "version": version or "Chưa tìm thấy Nmap",
        "scripts_dir": scripts_dir,
    }


def list_nse_scripts(scripts_dir: str) -> list[str]:
    """Liệt kê tên các NSE script có sẵn trong bản cài Nmap."""
    if not scripts_dir or not os.path.isdir(scripts_dir):
        return []
    return sorted(p.stem for p in Path(scripts_dir).glob("*.nse"))


# ─────────────────────────────────────────────────────────
#  DỰNG CÂU LỆNH
# ─────────────────────────────────────────────────────────

def validate_targets(target_text: str) -> tuple[list[str], str]:
    """Tách và kiểm tra danh sách mục tiêu (IP, dải IP, CIDR, hostname)."""
    items = [t for t in re.split(r"[\s;]+", target_text.strip()) if t]
    if not items:
        return [], "Chưa nhập mục tiêu."
    for t in items:
        if t.startswith("-") or not _TARGET_RE.match(t):
            return [], f"Mục tiêu không hợp lệ: '{t}'"
    return items, ""


def sanitize_extra_args(extra: str) -> tuple[list[str], str]:
    """Tách tham số bổ sung; chặn các tùy chọn ghi/đọc file."""
    if not extra.strip():
        return [], ""
    try:
        parts = shlex.split(extra, posix=False)
    except ValueError as e:
        return [], f"Tham số bổ sung không hợp lệ: {e}"
    for p in parts:
        if p.startswith(_BLOCKED_ARG_PREFIXES):
            return [], f"Không cho phép tùy chọn '{p}' (Web tự quản lý file kết quả)."
    return parts, ""


def build_nmap_command(
    nmap_path: str,
    targets: list[str],
    profile: str,
    ports: str = "",
    timing: str = "",
    skip_ping: bool = False,
    scripts: list[str] | None = None,
    script_args: str = "",
    verbose: bool = True,
    extra_args: list[str] | None = None,
) -> list[str]:
    cfg = SCAN_PROFILES[profile]
    cmd = [nmap_path] + list(cfg["args"])

    if cfg["uses_ports"] and ports.strip():
        cmd += ["-p", ports.strip().replace(" ", "")]

    if scripts:
        if "--script" in cmd:
            idx = cmd.index("--script")
            existing = cmd[idx + 1].split(",")
            merged = list(dict.fromkeys(existing + list(scripts)))
            cmd[idx + 1] = ",".join(merged)
        else:
            cmd += ["--script", ",".join(scripts)]
    if script_args.strip():
        cmd += ["--script-args", script_args.strip()]

    if timing:
        cmd.append(timing)
    if skip_ping and "-sn" not in cfg["args"]:
        cmd.append("-Pn")
    if verbose:
        cmd.append("-v")
    cmd.append("--reason")
    if extra_args:
        cmd += extra_args
    cmd += targets
    return cmd


def display_command(cmd: list[str]) -> str:
    """Chuỗi lệnh hiển thị cho người dùng (thay đường dẫn exe bằng 'nmap')."""
    shown = ["nmap"] + cmd[1:]
    return " ".join(f'"{c}"' if " " in c else c for c in shown)


# ─────────────────────────────────────────────────────────
#  THỰC THI
# ─────────────────────────────────────────────────────────

def run_nmap_streaming(cmd: list[str], timeout: int = 600, on_line=None) -> dict:
    """
    Chạy Nmap, ghi XML vào file tạm, đọc stdout từng dòng.
    Trả về dict gồm output thô, XML, mã thoát, thời gian.
    """
    fd, xml_path = tempfile.mkstemp(suffix=".xml", prefix="nmap_")
    os.close(fd)
    full_cmd = [cmd[0], "-oX", xml_path] + cmd[1:]

    started = datetime.now()
    lines: list[str] = []
    returncode = -1
    try:
        proc = subprocess.Popen(
            full_cmd, stdout=subprocess.PIPE, stderr=subprocess.STDOUT,
            text=True, encoding="utf-8", errors="replace", bufsize=1,
        )
        for line in proc.stdout:
            lines.append(line.rstrip("\n"))
            if on_line:
                on_line("\n".join(lines))
            if (datetime.now() - started).total_seconds() > timeout:
                proc.kill()
                lines.append(f"[Đã dừng] Vượt quá thời gian chờ {timeout}s.")
                break
        returncode = proc.wait(timeout=10)
    except Exception as e:
        lines.append(f"[Lỗi] Không thể chạy Nmap: {e}")

    xml_text = ""
    try:
        xml_text = Path(xml_path).read_text(encoding="utf-8", errors="replace")
    except Exception:
        pass
    finally:
        try:
            os.remove(xml_path)
        except OSError:
            pass

    return {
        "returncode": returncode,
        "raw_output": "\n".join(lines),
        "xml": xml_text,
        "started": started.strftime("%d/%m/%Y %H:%M:%S"),
        "duration_s": round((datetime.now() - started).total_seconds(), 1),
    }


def run_nping(nping_path: str, args: list[str], timeout: int = 60) -> dict:
    """Chạy Nping với danh sách tham số đã dựng sẵn."""
    started = datetime.now()
    try:
        proc = subprocess.run(
            [nping_path] + args, capture_output=True, text=True,
            timeout=timeout, encoding="utf-8", errors="replace",
        )
        out = (proc.stdout or "") + (("\n" + proc.stderr) if proc.stderr else "")
        rc = proc.returncode
    except subprocess.TimeoutExpired:
        out, rc = f"[Đã dừng] Vượt quá thời gian chờ {timeout}s.", -1
    except Exception as e:
        out, rc = f"[Lỗi] {e}", -1

    m = re.search(r"Raw packets sent:\s*(\d+).*?Rcvd:\s*(\d+).*?Lost:\s*(\d+)\s*\(([\d\.]+)%\)", out, re.S)
    stats = None
    if m:
        stats = {"sent": int(m.group(1)), "rcvd": int(m.group(2)),
                 "lost": int(m.group(3)), "loss_pct": float(m.group(4))}
    return {
        "returncode": rc,
        "raw_output": out.strip(),
        "stats": stats,
        "started": started.strftime("%d/%m/%Y %H:%M:%S"),
    }


# ─────────────────────────────────────────────────────────
#  PHÂN TÍCH XML
# ─────────────────────────────────────────────────────────

def parse_nmap_xml(xml_text: str) -> dict:
    """Chuyển XML của Nmap thành dict {hosts: [...], stats: {...}}."""
    result = {"hosts": [], "stats": {}, "error": ""}
    if not xml_text.strip():
        result["error"] = "Nmap không sinh ra dữ liệu XML."
        return result
    try:
        root = ET.fromstring(xml_text)
    except ET.ParseError as e:
        result["error"] = f"XML không hoàn chỉnh (có thể quét bị dừng giữa chừng): {e}"
        return result

    rs = root.find("runstats")
    if rs is not None:
        fin = rs.find("finished")
        hs = rs.find("hosts")
        result["stats"] = {
            "elapsed": fin.get("elapsed") if fin is not None else "",
            "summary": fin.get("summary") if fin is not None else "",
            "up": int(hs.get("up", 0)) if hs is not None else 0,
            "down": int(hs.get("down", 0)) if hs is not None else 0,
            "total": int(hs.get("total", 0)) if hs is not None else 0,
        }

    for h in root.findall("host"):
        status = h.find("status")
        addr_ip, addr_mac, vendor = "", "", ""
        for a in h.findall("address"):
            if a.get("addrtype") in ("ipv4", "ipv6"):
                addr_ip = a.get("addr", "")
            elif a.get("addrtype") == "mac":
                addr_mac = a.get("addr", "")
                vendor = a.get("vendor", "")
        hostnames = [hn.get("name", "") for hn in h.findall("hostnames/hostname")]

        os_matches = [
            {"name": om.get("name", ""), "accuracy": om.get("accuracy", "")}
            for om in h.findall("os/osmatch")
        ][:3]

        ports = []
        for p in h.findall("ports/port"):
            st = p.find("state")
            sv = p.find("service")
            scripts = [
                {"id": s.get("id", ""), "output": (s.get("output") or "").strip()}
                for s in p.findall("script")
            ]
            ports.append({
                "port": int(p.get("portid", 0)),
                "protocol": p.get("protocol", ""),
                "state": st.get("state", "") if st is not None else "",
                "reason": st.get("reason", "") if st is not None else "",
                "service": sv.get("name", "") if sv is not None else "",
                "product": sv.get("product", "") if sv is not None else "",
                "version": sv.get("version", "") if sv is not None else "",
                "extrainfo": sv.get("extrainfo", "") if sv is not None else "",
                "scripts": scripts,
            })

        host_scripts = [
            {"id": s.get("id", ""), "output": (s.get("output") or "").strip()}
            for s in h.findall("hostscript/script")
        ]

        result["hosts"].append({
            "ip": addr_ip,
            "mac": addr_mac,
            "vendor": vendor,
            "hostnames": ", ".join(n for n in hostnames if n),
            "status": status.get("state", "") if status is not None else "",
            "status_reason": status.get("reason", "") if status is not None else "",
            "os": os_matches,
            "ports": ports,
            "host_scripts": host_scripts,
        })
    return result


# ─────────────────────────────────────────────────────────
#  ENGINE ĐÁNH GIÁ AN NINH & CHỨNG MINH TẤN CÔNG / PHÒNG THỦ
# ─────────────────────────────────────────────────────────

def evaluate_nmap_security_findings(parsed: dict, raw_output: str) -> list[dict]:
    """
    Tự động phân tích kết quả thực tế của Nmap sau khi quét để:
      - Chứng minh lỗ hổng / điểm yếu (FAIL ❌) hoặc xác nhận đã phòng thủ thành công (PASS ✅).
      - Giải thích kịch bản tấn công (Attack Scenario) và khuyến nghị lệnh phòng thủ (Defense Command).
    """
    findings: list[dict] = []
    hosts = parsed.get("hosts", [])

    if not hosts:
        findings.append({
            "check_key": "host_reachability",
            "verdict": "WARN",
            "badge": "WARN ⚠️ (KHÔNG PHÁT HIỆN HOST PHẢN HỒI)",
            "severity": "Info",
            "title": "Mục tiêu không phản hồi gói tin thăm dò (Host Down hoặc Chặn Ping)",
            "evidence": "0 hosts up",
            "attack_scenario": (
                "Máy mục tiêu có thể đang tắt, khác dải mạng, hoặc Tường lửa đã chặn gói tin Ping (ICMP Echo/ARP). "
                "Kẻ tấn công thường sẽ bật tùy chọn '-Pn' để bỏ qua bước kiểm tra Ping và quét thẳng vào các cổng TCP."
            ),
            "recommendation": "Nếu máy mục tiêu đang bật mà bị tường lửa chặn Ping, hãy tích chọn ô '-Pn' trên giao diện rồi bấm Chạy Nmap lại.",
            "remediation_cmd": "",
        })
        return findings

    for h in hosts:
        ip = h["ip"]
        all_scripts = list(h.get("host_scripts", []))
        for p in h.get("ports", []):
            for s in p.get("scripts", []):
                all_scripts.append({"id": f"{s['id']} (port {p['port']})", "raw_id": s["id"], "output": s["output"]})

        # 1. Phân tích kết quả các NSE Script nếu có chạy
        for s in all_scripts:
            sid = s.get("raw_id", s["id"])
            sout = s.get("output", "")
            sout_low = sout.lower()

            # 1a. Kiểm định SMB Signing (smb2-security-mode / smb-security-mode)
            if "smb2-security-mode" in sid or "smb-security-mode" in sid:
                if "enabled but not required" in sout_low or "signing disabled" in sout_low:
                    findings.append({
                        "check_key": f"{ip}:smb_signing",
                        "verdict": "FAIL",
                        "badge": "FAIL ❌ (PHÁT HIỆN LỖ HỔNG — CÓ THỂ BỊ TẤN CÔNG MITM / SMB RELAY)",
                        "severity": "Medium",
                        "title": f"[{ip}] Giao thức SMB KHÔNG bắt buộc chữ ký số (Nessus Plugin 57608)",
                        "evidence": f"Script '{sid}' trả về: {sout.strip()}",
                        "attack_scenario": (
                            "Kịch bản tấn công (Red Team): Do máy chủ không bắt buộc ký số gói tin SMB, kẻ tấn công trong mạng LAN "
                            "có thể thực hiện ARP Spoofing / LLMNR Poisoning (bằng công cụ Responder + ntlmrelayx) để đứng giữa "
                            "(Man-in-the-Middle), chặn bắt và chuyển tiếp xác thực NTLM (SMB Relay) nhằm chiếm quyền thực thi lệnh trên máy mục tiêu."
                        ),
                        "recommendation": (
                            "Khuyến nghị phòng thủ (Blue Team): Bật chính sách bắt buộc ký số (RequireSecuritySignature = 1) "
                            "trên SMB Server và SMB Client để đảm bảo tính toàn vẹn của mọi gói tin qua cổng 445."
                        ),
                        "remediation_cmd": (
                            "# Chạy PowerShell (Run as Administrator) trên máy mục tiêu:\n"
                            "Set-SmbServerConfiguration -RequireSecuritySignature $true -EnableSecuritySignature $true -Force\n"
                            'Set-ItemProperty -Path "HKLM:\\SYSTEM\\CurrentControlSet\\Services\\LanmanServer\\Parameters" -Name "RequireSecuritySignature" -Value 1 -Type DWord -Force'
                        ),
                    })
                elif "enabled and required" in sout_low:
                    findings.append({
                        "check_key": f"{ip}:smb_signing",
                        "verdict": "PASS",
                        "badge": "PASS ✅ (ĐÃ PHÒNG THỦ AN TOÀN — CHẶN ĐỨNG SMB RELAY)",
                        "severity": "Safe",
                        "title": f"[{ip}] Giao thức SMB đã BẮT BUỘC chữ ký số (SMB Signing Required)",
                        "evidence": f"Script '{sid}' trả về: {sout.strip()}",
                        "attack_scenario": (
                            "Chứng minh phòng thủ: Mọi gói tin SMB2/SMB3 trao đổi qua cổng 445 đều bắt buộc phải có chữ ký số hợp lệ. "
                            "Kịch bản tấn công giả mạo hoặc chuyển tiếp gói tin (NTLM/SMB Relay & Man-in-the-Middle) đã bị vô hiệu hóa hoàn toàn."
                        ),
                        "recommendation": "Duy trì cấu hình RequireSecuritySignature = True hiện tại.",
                        "remediation_cmd": "",
                    })

            # 1b. Kiểm định Giao thức SMBv1 / SMBv2 / SMBv3 (smb-protocols)
            elif "smb-protocols" in sid:
                if "nt lm 0.12" in sout_low or ("smbv1" in sout_low and "dangerous" in sout_low):
                    findings.append({
                        "check_key": f"{ip}:smb_protocols",
                        "verdict": "FAIL",
                        "badge": "FAIL ❌ (LỖ HỔNG NGHIÊM TRỌNG — ĐANG BẬT GIAO THỨC CŨ SMBv1)",
                        "severity": "High",
                        "title": f"[{ip}] Máy mục tiêu vẫn bật giao thức SMBv1 (Nguy cơ RCE EternalBlue MS17-010)",
                        "evidence": f"Script '{sid}' trả về: {sout.strip()}",
                        "attack_scenario": (
                            "Kịch bản tấn công: Giao thức SMBv1 đời cũ tồn tại các lỗ hổng thực thi mã từ xa kinh điển "
                            "(như MS17-010 EternalBlue / WannaCry) cho phép kẻ tấn công chiếm quyền SYSTEM mà không cần mật khẩu."
                        ),
                        "recommendation": "Vô hiệu hóa hoàn toàn giao thức SMBv1 trên hệ điều hành Windows.",
                        "remediation_cmd": "Set-SmbServerConfiguration -EnableSMB1Protocol $false -Force",
                    })
                else:
                    findings.append({
                        "check_key": f"{ip}:smb_protocols",
                        "verdict": "PASS",
                        "badge": "PASS ✅ (ĐÃ PHÒNG THỦ — CHỈ SỬ DỤNG SMBv2 / SMBv3 AN TOÀN)",
                        "severity": "Safe",
                        "title": f"[{ip}] Đã tắt SMBv1 — Hệ thống chỉ thương lượng giao thức SMB 2.x / 3.x",
                        "evidence": f"Script '{sid}' trả về: {sout.strip()}",
                        "attack_scenario": (
                            "Chứng minh phòng thủ: Máy chủ từ chối hoàn toàn giao thức SMBv1 cũ, loại bỏ bề mặt tấn công của dòng mã độc tự lây lan kiểu EternalBlue."
                        ),
                        "recommendation": "Tiếp tục duy trì chỉ sử dụng SMB 2.x/3.x kết hợp SMB Signing.",
                        "remediation_cmd": "",
                    })

            # 1c. Kiểm định chung các NSE script dò lỗ hổng (--script vuln hoặc tương đương)
            elif "vulnerable" in sout_low and "not vulnerable" not in sout_low:
                findings.append({
                    "check_key": f"{ip}:nse_{sid}",
                    "verdict": "FAIL",
                    "badge": "FAIL ❌ (NSE SCRIPT XÁC NHẬN CÓ LỖ HỔNG KHAI THÁC ĐƯỢC)",
                    "severity": "High",
                    "title": f"[{ip}] Script NSE '{sid}' phát hiện trạng thái VULNERABLE",
                    "evidence": sout.strip()[:500],
                    "attack_scenario": f"Kẻ tấn công có thể sử dụng module khai thác tương ứng với '{sid}' để xâm nhập dịch vụ.",
                    "recommendation": "Cập nhật bản vá bảo mật cho dịch vụ hoặc đóng cổng dịch vụ tương ứng trên tường lửa.",
                    "remediation_cmd": "",
                })
            elif "not vulnerable" in sout_low:
                findings.append({
                    "check_key": f"{ip}:nse_{sid}",
                    "verdict": "PASS",
                    "badge": "PASS ✅ (NSE SCRIPT XÁC NHẬN KHÔNG BỊ LỖ HỔNG)",
                    "severity": "Safe",
                    "title": f"[{ip}] Script NSE '{sid}' xác nhận hệ thống an toàn (NOT VULNERABLE)",
                    "evidence": sout.strip()[:400],
                    "attack_scenario": "Thử nghiệm thăm dò lỗ hổng của Nmap NSE đã bị hệ thống từ chối hoặc bản vá đã được áp dụng.",
                    "recommendation": "Duy trì bản vá hiện tại.",
                    "remediation_cmd": "",
                })

        # 2. Phân tích từng Cổng dịch vụ Mở (Open) vs. Đã lọc/Đóng (Filtered/Closed)
        open_ports = [p for p in h.get("ports", []) if p.get("state") == "open"]
        blocked_ports = [p for p in h.get("ports", []) if p.get("state") in ("filtered", "closed")]

        for p in open_ports:
            pnum = int(p["port"])
            proto = p["protocol"]
            svc_str = " ".join(x for x in [p.get("service", ""), p.get("product", ""), p.get("version", "")] if x).strip()
            kb = PORT_SECURITY_KNOWLEDGE.get(pnum)

            if kb:
                findings.append({
                    "check_key": f"{ip}:port_{pnum}_{proto}",
                    "verdict": "WARN" if kb["severity"] in ("Low", "Medium") else "FAIL",
                    "badge": f"WARN ⚠️ (CỔNG {pnum}/{proto.upper()} ĐANG MỞ — BỀ MẶT TẤN CÔNG)",
                    "severity": kb["severity"],
                    "title": f"[{ip}] Cổng {pnum}/{proto} ({kb['name']}) đang mở cho kết nối mạng",
                    "evidence": f"Nmap ghi nhận: {pnum}/{proto} OPEN — Dịch vụ: {svc_str or kb['name']} (reason: {p.get('reason', 'syn-ack')})",
                    "attack_scenario": f"Kịch bản tấn công: {kb['attack']}",
                    "recommendation": f"Khuyến nghị phòng thủ: {kb['defense']}",
                    "remediation_cmd": kb["cmd"],
                })
            else:
                findings.append({
                    "check_key": f"{ip}:port_{pnum}_{proto}",
                    "verdict": "WARN",
                    "badge": f"WARN ⚠️ (PHÁT HIỆN CỔNG {pnum}/{proto.upper()} MỞ)",
                    "severity": "Low",
                    "title": f"[{ip}] Cổng dịch vụ {pnum}/{proto} ({svc_str or 'unknown'}) đang mở",
                    "evidence": f"Nmap ghi nhận: {pnum}/{proto} OPEN — Dịch vụ: {svc_str or 'chưa rõ phiên bản'}",
                    "attack_scenario": (
                        f"Kẻ tấn công có thể kết nối tới cổng {pnum}/{proto} để thu thập banner phiên bản phần mềm "
                        "và tìm kiếm mã khai thác (Exploit) tương ứng với phiên bản dịch vụ đó."
                    ),
                    "recommendation": f"Kiểm tra xem dịch vụ trên cổng {pnum} có thực sự cần thiết không; nếu không cần chia sẻ qua mạng, hãy chặn trên Firewall.",
                    "remediation_cmd": f'New-NetFirewallRule -DisplayName "Block_Port_{pnum}" -Direction Inbound -LocalPort {pnum} -Protocol {proto.upper()} -Action Block',
                })

        # Nếu người dùng quét cụ thể một số cổng (1-10 cổng) và tất cả hoặc một số cổng đã bị chặn (filtered/closed)
        if blocked_ports and len(h.get("ports", [])) <= 10:
            blocked_str = ", ".join(f"{p['port']}/{p['protocol']} ({p['state']})" for p in blocked_ports)
            findings.append({
                "check_key": f"{ip}:blocked_ports",
                "verdict": "PASS",
                "badge": "PASS ✅ (TƯỜNG LỬA / HỆ THỐNG ĐÃ ĐÓNG CÁC CỔNG NÀY)",
                "severity": "Safe",
                "title": f"[{ip}] Các cổng được kiểm tra đang ở trạng thái Đóng / Đã lọc bởi Tường lửa",
                "evidence": f"Nmap ghi nhận: {blocked_str}",
                "attack_scenario": (
                    "Chứng minh phòng thủ: Gói tin thăm dò SYN của Nmap tới các cổng này đã bị từ chối (RST) hoặc bị Tường lửa đánh rơi (Filtered/No-response), "
                    "kẻ tấn công không thể thiết lập kết nối TCP tới dịch vụ."
                ),
                "recommendation": "Cấu hình khóa cổng hiện tại đã an toàn.",
                "remediation_cmd": "",
            })

    return findings


def evaluate_nping_security_findings(mode: str, args: list[str], raw_output: str, stats: dict | None) -> list[dict]:
    """
    Phân tích kết quả bắn gói tin thực tế của Nping (ICMP / TCP / UDP) để chứng minh
    kịch bản Tấn công thăm dò vs. Phòng thủ Tường lửa (PASS ✅ / FAIL ❌).
    """
    findings: list[dict] = []
    out_low = raw_output.lower()
    cmd_str = "nping " + " ".join(args)

    rcvd = stats["rcvd"] if stats else (1 if "rcvd" in out_low else 0)
    sent = stats["sent"] if stats else 0
    loss_pct = stats["loss_pct"] if stats else (0.0 if rcvd > 0 else 100.0)

    # Kịch bản 1: Kiểm định ICMP Timestamp Request (Type 13) -> CVE-1999-0524 (Nessus Plugin 10114)
    if mode == "ICMP" and "--icmp-type" in args and "13" in args:
        if rcvd > 0 or "timestamp reply" in out_low or "type=14" in out_low:
            findings.append({
                "check_key": "nping_icmp_13",
                "verdict": "FAIL",
                "badge": "FAIL ❌ (PHÁT HIỆN LỖ HỔNG CVE-1999-0524 — RÒ RỈ THỜI GIAN HỆ THỐNG)",
                "severity": "Medium",
                "title": "Máy mục tiêu phản hồi gói tin ICMP Timestamp Reply (Type 14) — Nessus Plugin 10114",
                "evidence": f"Lệnh '{cmd_str}' nhận được {rcvd}/{sent} gói phản hồi (ICMP Type 14 Timestamp Reply).",
                "attack_scenario": (
                    "Kịch bản tấn công (Red Team): Kẻ tấn công gửi gói tin ICMP Type 13 và máy mục tiêu lập tức trả lời gói Type 14 "
                    "chứa thời gian hệ thống chính xác tới mili-giây. Thông tin này giúp kẻ tấn công lập hồ sơ hệ thống (Fingerprinting), "
                    "xác định múi giờ/uptime hoặc tấn công đoán khóa ngẫu nhiên dựa trên thời gian (Time-seeded PRNG)."
                ),
                "recommendation": (
                    "Khuyến nghị phòng thủ (Blue Team): Tạo quy tắc trên Windows Defender Firewall chặn gói tin "
                    "ICMPv4 Type 13 (chiều vào - Inbound) và Type 14 (chiều ra - Outbound)."
                ),
                "remediation_cmd": (
                    "# Chạy PowerShell (Run as Administrator) trên máy mục tiêu để chặn ICMP Timestamp:\n"
                    'New-NetFirewallRule -DisplayName "Block_ICMP_Timestamp_In" -Direction Inbound -Protocol ICMPv4 -IcmpType 13 -Action Block -Profile Any -Enabled True\n'
                    'New-NetFirewallRule -DisplayName "Block_ICMP_Timestamp_Out" -Direction Outbound -Protocol ICMPv4 -IcmpType 14 -Action Block -Profile Any -Enabled True'
                ),
            })
        else:
            findings.append({
                "check_key": "nping_icmp_13",
                "verdict": "PASS",
                "badge": "PASS ✅ (ĐÃ PHÒNG THỦ — TƯỜNG LỬA CHẶN 100% ICMP TIMESTAMP)",
                "severity": "Safe",
                "title": "Tường lửa đã chặn triệt để gói tin thăm dò ICMP Timestamp (CVE-1999-0524)",
                "evidence": f"Lệnh '{cmd_str}': Đã gửi {sent} gói ICMP Type 13 | Nhận phản hồi: 0 (Lost: {loss_pct}%).",
                "attack_scenario": (
                    "Chứng minh phòng thủ: Gói tin thăm dò ICMP Type 13 do Nping bắn tới đã bị Windows Defender Firewall "
                    "đánh rơi hoàn toàn (Drop 100%). Kẻ tấn công không thu thập được mốc thời gian hệ thống (Khắc phục thành công Nessus Plugin 10114)."
                ),
                "recommendation": "Quy tắc tường lửa chặn ICMP Type 13/14 đang hoạt động hiệu quả.",
                "remediation_cmd": "",
            })
        return findings

    # Kịch bản 2: Các loại gói tin ICMP khác hoặc TCP / UDP probe
    if rcvd > 0:
        findings.append({
            "check_key": f"nping_{mode}",
            "verdict": "WARN",
            "badge": f"WARN ⚠️ (MỤC TIÊU CÓ PHẢN HỒI GÓI TIN {mode} — RCVD: {rcvd}/{sent})",
            "severity": "Low",
            "title": f"Mục tiêu phản hồi gói tin thăm dò {mode} ({rcvd}/{sent} gói)",
            "evidence": f"Lệnh '{cmd_str}' nhận lại {rcvd} gói phản hồi (Tỷ lệ mất: {loss_pct}%).",
            "attack_scenario": (
                f"Kẻ tấn công sử dụng gói thăm dò {mode} để xác nhận máy chủ đang hoạt động (Host Discovery) "
                "và kiểm tra quy tắc lọc gói tin (Firewall Rule Mapping / ACK-SYN probing)."
            ),
            "recommendation": "Nếu không muốn máy chủ bị lộ diện trước các công cụ dò quét mạng, hãy cấu hình Firewall chặn loại gói thăm dò này.",
            "remediation_cmd": "",
        })
    else:
        findings.append({
            "check_key": f"nping_{mode}",
            "verdict": "PASS",
            "badge": f"PASS ✅ (KHÔNG PHẢN HỒI GÓI THĂM DÒ {mode} — LOST: 100%)",
            "severity": "Safe",
            "title": f"Tường lửa đã chặn hoặc mục tiêu không phản hồi gói thăm dò {mode}",
            "evidence": f"Lệnh '{cmd_str}': Gửi {sent} gói | Nhận: 0 (Lost: 100%).",
            "attack_scenario": "Gói tin thăm dò bị đánh rơi hoàn toàn, giúp ẩn trạng thái dịch vụ trước công cụ rà quét.",
            "recommendation": "Duy trì chính sách lọc gói hiện tại.",
            "remediation_cmd": "",
        })

    return findings


def compare_security_verdicts(findings_before: list[dict], findings_after: list[dict]) -> list[dict]:
    """
    Đối chiếu danh sách phát hiện an ninh giữa 2 lần chạy Nmap (Trước khi phòng thủ vs. Sau khi phòng thủ)
    để chứng minh sự chuyển đổi trạng thái (VD: FAIL ❌ -> PASS ✅).
    """
    map_a = {f["check_key"]: f for f in findings_before}
    map_b = {f["check_key"]: f for f in findings_after}
    all_keys = list(dict.fromkeys(list(map_a.keys()) + list(map_b.keys())))

    rows = []
    for k in all_keys:
        fa = map_a.get(k)
        fb = map_b.get(k)
        va = fa["verdict"] if fa else "—"
        vb = fb["verdict"] if fb else "—"
        title = (fb or fa)["title"]

        if va in ("FAIL", "WARN") and vb == "PASS":
            proof = "✅ ĐÃ PHÒNG THỦ THÀNH CÔNG (FAIL/WARN → PASS)"
        elif va == "PASS" and vb in ("FAIL", "WARN"):
            proof = "❌ MỞ LẠI LỖI / SUY GIẢM AN NINH (PASS → FAIL/WARN)"
        elif va == vb == "FAIL":
            proof = "⚠️ LỖ HỔNG VẪN CÒN TỒN TẠI (FAIL → FAIL)"
        elif va == vb == "PASS":
            proof = "🛡️ DUY TRÌ AN TOÀN (PASS → PASS)"
        else:
            proof = f"{va} → {vb}"

        rows.append({
            "Hạng mục Kiểm định": title,
            "Trước (Lần chạy A)": fa["badge"] if fa else "Không có",
            "Sau (Lần chạy B)": fb["badge"] if fb else "Không có",
            "Bằng chứng Sau khi Phòng thủ": fb["evidence"] if fb else (fa["evidence"] if fa else ""),
            "Kết luận Chứng minh": proof,
        })
    return rows


def nping_icmp_args(target: str, icmp_type: int, count: int) -> list[str]:
    return ["--icmp", "--icmp-type", str(icmp_type), "-c", str(count), target]


def nping_tcp_args(target: str, ports: str, flags: str, count: int) -> list[str]:
    return ["--tcp", "-p", ports, "--flags", flags, "-c", str(count), target]


def nping_udp_args(target: str, ports: str, count: int) -> list[str]:
    return ["--udp", "-p", ports, "-c", str(count), target]
