"""
analyzer.py - Logic gọi LLM (Google Gemini / OpenAI) để phân tích lỗ hổng.

Cung cấp prompt template chuyên sâu cho SOC/Security Engineer,
diễn giải nguyên nhân, rủi ro, khắc phục và lệnh xác minh.
"""

import json
from typing import Optional

import sys, os
sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
from config import Settings


# ═══════════════════════════════════════════════════════════
#  PROMPT TEMPLATE
# ═══════════════════════════════════════════════════════════

ANALYSIS_PROMPT_TEMPLATE = """Bạn là một Chuyên gia An toàn thông tin cấp cao (Senior Cybersecurity Analyst / SOC Specialist) với hơn 15 năm kinh nghiệm phân tích lỗ hổng bảo mật.

Nhiệm vụ: Phân tích chi tiết lỗ hổng bảo mật sau đây từ kết quả quét Nessus và đưa ra hướng dẫn khắc phục chuyên sâu.

═══════════════════════════════════════════
THÔNG TIN LỖ HỔNG
═══════════════════════════════════════════
- Plugin ID: {plugin_id}
- Tên lỗ hổng: {plugin_name}
- Họ plugin: {plugin_family}
- Mức nghiêm trọng: {severity_label} (Severity: {severity})
- CVSS v2 Base Score: {cvss_base}
- CVSS v3 Base Score: {cvss3_base}
- CVE: {cve_list}
- Host bị ảnh hưởng: {host_ip} (Port: {port}/{protocol})
- Exploit có sẵn: {exploit_available}

Tóm tắt (Synopsis):
{synopsis}

Mô tả chi tiết:
{description}

Giải pháp từ Nessus:
{solution}

Output từ plugin:
{plugin_output}

Tham khảo:
{see_also}
═══════════════════════════════════════════

Hãy phân tích và trả lời theo đúng cấu trúc JSON sau (KHÔNG thêm markdown, KHÔNG thêm ```json):

{{
    "root_cause": "Phân tích nguyên nhân gốc rễ của lỗ hổng, kèm bằng chứng cụ thể từ plugin output và mô tả kỹ thuật. Giải thích TẠI SAO lỗ hổng này xuất hiện trên hệ thống.",
    "risk_explanation": "Diễn giải rủi ro thực tế bằng ngôn ngữ dễ hiểu cho cả quản lý và kỹ thuật. Mô tả kịch bản tấn công có thể xảy ra, mức độ ảnh hưởng đến tính Bảo mật (C), Toàn vẹn (I), Khả dụng (A) của hệ thống.",
    "remediation_steps": "Hướng dẫn từng bước khắc phục chi tiết, bao gồm:\\n1. Bước chuẩn bị (backup, thông báo)\\n2. Các lệnh/thao tác cụ thể để vá lỗi (phân biệt Windows/Linux nếu cần)\\n3. Cấu hình bổ sung để hardening\\n4. Kiểm tra sau khi vá",
    "powershell_script": "Đoạn mã PowerShell (.ps1) hoàn chỉnh, chạy dưới quyền Administrator để tự động khắc phục triệt để lỗ hổng này trên Windows (có chú thích tiếng Việt rõ ràng).",
    "verification_cmds": "Danh sách các lệnh cụ thể (command-line / PowerShell) để kiểm tra xem lỗ hổng đã được khắc phục thành công chưa. Ví dụ: lệnh kiểm tra version, kiểm tra Registry, kiểm tra Firewall rule...",
    "priority_score": 8,
    "additional_notes": "Các lưu ý bổ sung: tác động phụ khi vá, workaround tạm thời nếu chưa thể vá ngay, tài liệu tham khảo thêm."
}}

Lưu ý quan trọng:
- priority_score là số nguyên từ 1-10 (10 = khẩn cấp nhất).
- Nếu có exploit sẵn, tăng priority_score lên ít nhất 7.
- Luôn đề cập CVE cụ thể nếu có.
- Lệnh verification phải thực tế, có thể chạy được ngay trên server.
- Trả lời bằng tiếng Việt."""


BATCH_SUMMARY_PROMPT = """Bạn là Chuyên gia An toàn thông tin. Hãy tóm tắt tổng quan kết quả quét lỗ hổng sau:

Tổng số lỗ hổng: {total}
- Critical: {critical}
- High: {high}
- Medium: {medium}
- Low: {low}
- Info: {info}

Danh sách top lỗ hổng nghiêm trọng nhất:
{top_vulns}

Hãy viết bản tóm tắt ngắn gọn (3-5 đoạn) bằng tiếng Việt gồm:
1. Đánh giá tổng thể mức độ an toàn của hệ thống.
2. Các rủi ro đáng lo ngại nhất cần xử lý ngay.
3. Đề xuất thứ tự ưu tiên khắc phục.
4. Khuyến nghị chung về cải thiện bảo mật."""


# ═══════════════════════════════════════════════════════════
#  AI CLIENT FACTORY
# ═══════════════════════════════════════════════════════════

def _call_gemini(prompt: str) -> str:
    """Gọi Google Gemini API với cơ chế tự động fallback model nếu gặp lỗi deprecation/404."""
    from google import genai

    client = genai.Client(api_key=Settings.get_active_api_key())
    preferred_model = Settings.get_model_name()
    
    # Danh sách model dự phòng linh hoạt
    candidate_models = [preferred_model]
    for fallback in ["gemini-3.1-flash-lite", "gemini-3.5-flash-lite", "gemini-3.8-flash", "gemini-2.5-flash"]:
        if fallback not in candidate_models:
            candidate_models.append(fallback)

    last_error = None
    for model in candidate_models:
        try:
            response = client.models.generate_content(
                model=model,
                contents=prompt,
            )
            return response.text
        except Exception as e:
            last_error = e
            err_msg = str(e).lower()
            if "404" in err_msg or "not_found" in err_msg or "no longer available" in err_msg:
                continue
            raise e

    if last_error:
        raise last_error
    return ""


def _call_openai(prompt: str) -> str:
    """Gọi OpenAI API."""
    from openai import OpenAI

    client = OpenAI(api_key=Settings.get_active_api_key())
    response = client.chat.completions.create(
        model=Settings.get_model_name(),
        messages=[
            {
                "role": "system",
                "content": "Bạn là chuyên gia phân tích lỗ hổng bảo mật hàng đầu. Luôn trả lời bằng tiếng Việt.",
            },
            {"role": "user", "content": prompt},
        ],
        temperature=0.3,
    )
    return response.choices[0].message.content


def _call_llm(prompt: str) -> str:
    """Router: gọi LLM đúng provider đã cấu hình."""
    provider = Settings.AI_PROVIDER
    if provider == "openai":
        return _call_openai(prompt)
    return _call_gemini(prompt)


# ═══════════════════════════════════════════════════════════
#  PUBLIC API
# ═══════════════════════════════════════════════════════════

def analyze_vulnerability(vuln: dict) -> dict:
    """
    Phân tích 1 lỗ hổng bằng AI.

    Args:
        vuln: dict chứa thông tin lỗ hổng (từ DB hoặc DataFrame row).

    Returns:
        dict với các key: root_cause, risk_explanation, remediation_steps,
        verification_cmds, priority_score, additional_notes
    """
    prompt = ANALYSIS_PROMPT_TEMPLATE.format(
        plugin_id=vuln.get("plugin_id", "N/A"),
        plugin_name=vuln.get("plugin_name", "N/A"),
        plugin_family=vuln.get("plugin_family", "N/A"),
        severity_label=vuln.get("severity_label", "N/A"),
        severity=vuln.get("severity", 0),
        cvss_base=vuln.get("cvss_base_score", "N/A"),
        cvss3_base=vuln.get("cvss3_base_score", "N/A"),
        cve_list=vuln.get("cve_list", "N/A"),
        host_ip=vuln.get("host_ip", "N/A"),
        port=vuln.get("port", "N/A"),
        protocol=vuln.get("protocol", "N/A"),
        exploit_available="Có" if vuln.get("exploit_available") else "Không",
        synopsis=vuln.get("synopsis", "N/A"),
        description=vuln.get("description", "N/A"),
        solution=vuln.get("solution", "N/A"),
        plugin_output=vuln.get("plugin_output", "N/A")[:3000],  # Giới hạn output
        see_also=vuln.get("see_also", "N/A"),
    )

    raw_response = _call_llm(prompt)

    # Parse JSON response từ AI
    try:
        # Loại bỏ markdown code block nếu có
        cleaned = raw_response.strip()
        if cleaned.startswith("```"):
            cleaned = cleaned.split("\n", 1)[1]
        if cleaned.endswith("```"):
            cleaned = cleaned.rsplit("```", 1)[0]
        cleaned = cleaned.strip()

        result = json.loads(cleaned)
    except json.JSONDecodeError:
        # Fallback: trả về raw text nếu không parse được JSON
        result = {
            "root_cause": raw_response,
            "risk_explanation": "",
            "remediation_steps": "",
            "verification_cmds": "",
            "priority_score": vuln.get("severity", 0) * 2 + 1,
            "additional_notes": "⚠️ AI trả về dạng text thay vì JSON. Xem root_cause để đọc phân tích đầy đủ.",
        }

    # Đảm bảo priority_score hợp lệ
    try:
        ps = int(result.get("priority_score", 5))
        result["priority_score"] = max(1, min(10, ps))
    except (ValueError, TypeError):
        result["priority_score"] = vuln.get("severity", 0) * 2 + 1

    return result


def generate_scan_summary(stats: dict, top_vulns_text: str) -> str:
    """
    Tạo bản tóm tắt tổng quan phiên quét bằng AI.

    Args:
        stats: dict {"total": int, "critical": int, "high": int, ...}
        top_vulns_text: Chuỗi mô tả top lỗ hổng nghiêm trọng

    Returns:
        str: Bản tóm tắt tiếng Việt
    """
    prompt = BATCH_SUMMARY_PROMPT.format(
        total=stats.get("total", 0),
        critical=stats.get("critical", 0),
        high=stats.get("high", 0),
        medium=stats.get("medium", 0),
        low=stats.get("low", 0),
        info=stats.get("info", 0),
        top_vulns=top_vulns_text,
    )
    return _call_llm(prompt)


def test_ai_connection() -> tuple[bool, str]:
    """
    Kiểm tra kết nối AI API.

    Returns:
        (True, "Kết nối thành công...") hoặc (False, "Lỗi...")
    """
    api_key = Settings.get_active_api_key()
    if not api_key:
        return False, (
            f"❌ Chưa cấu hình API key cho provider '{Settings.AI_PROVIDER}'.\n"
            f"Hãy điền {'GEMINI_API_KEY' if Settings.AI_PROVIDER == 'gemini' else 'OPENAI_API_KEY'} trong file .env"
        )

    try:
        response = _call_llm("Trả lời đúng 1 từ: OK")
        return True, f"✅ AI API ({Settings.AI_PROVIDER} / {Settings.get_model_name()}) hoạt động bình thường."
    except Exception as e:
        return False, f"❌ Lỗi kết nối AI API ({Settings.AI_PROVIDER}):\n{type(e).__name__}: {e}"


def build_standard_lab_remediation_ps1(target_ip: str = "192.168.104.129") -> str:
    """
    Sinh kịch bản PowerShell (.ps1) chuẩn xác 100% cho môi trường Lab Windows 11
    xử lý triệt để 4 nhóm lỗ hổng thực nghiệm:
      1. VLC Media Player < 2.2.x (Critical CVSS 9.8)
      2. WinVerifyTrust Signature Validation CVE-2013-3900 (High CVSS 8.8)
      3. ICMP Timestamp Request Remote Date Disclosure CVE-1999-0524 (Medium)
      4. SMB Signing not required (Medium)
    """
    return f"""# ==============================================================================
#  NESSUS AI AUTO-REMEDIATION SCRIPT (POWERSHELL)
#  Target Machine : Windows 11 Pro ({target_ip})
#  Generated by   : Nessus AI Security Assistant (Phương án A)
#  Yêu cầu        : Chạy PowerShell với quyền Administrator (Run as Administrator)
# ==============================================================================

#Requires -RunAsAdministrator
$ErrorActionPreference = "Continue"

Write-Host "================================================================" -ForegroundColor Cyan
Write-Host "  BAT DAU QUY TRINH TU DONG KHAC PHUC LO HONG (AUTO-REMEDIATION)" -ForegroundColor Cyan
Write-Host "================================================================" -ForegroundColor Cyan

# ------------------------------------------------------------------------------
# [1/4] Khắc phục lỗ hổng CRITICAL (CVSS 9.8): Gỡ bỏ VLC Media Player lỗi thời
# ------------------------------------------------------------------------------
Write-Host "`n[1/4] Kiem tra va go bo phien ban VLC Media Player cu (2.2.0)..." -ForegroundColor Yellow
$vlcPaths = @(
    "C:\\Program Files\\VideoLAN\\VLC\\uninstall.exe",
    "C:\\Program Files (x86)\\VideoLAN\\VLC\\uninstall.exe"
)
$vlcFound = $false
foreach ($path in $vlcPaths) {{
    if (Test-Path $path) {{
        $vlcFound = $true
        Write-Host "  -> Phat hien VLC tai: $path. Dang tien hanh go cai dat silent..." -ForegroundColor Magenta
        Start-Process -FilePath $path -ArgumentList "/S" -Wait -NoNewWindow
        Start-Sleep -Seconds 2
        $dir = Split-Path $path -Parent
        if (Test-Path $dir) {{
            Remove-Item -Path $dir -Recurse -Force -ErrorAction SilentlyContinue
        }}
        Write-Host "  [OK] Da go bo va don sach thu muc VLC." -ForegroundColor Green
    }}
}}
if (-not $vlcFound) {{
    Write-Host "  [INFO] Khong tim thay VLC cu hoac da duoc go bo truoc do." -ForegroundColor Gray
}}

# ------------------------------------------------------------------------------
# [2/4] Khắc phục lỗ hổng HIGH (CVSS 8.8): WinVerifyTrust Signature Validation (CVE-2013-3900)
# ------------------------------------------------------------------------------
Write-Host "`n[2/4] Cau hinh Registry EnableCertPaddingCheck (CVE-2013-3900)..." -ForegroundColor Yellow
$wintrustPaths = @(
    "HKLM:\\Software\\Microsoft\\Cryptography\\Wintrust\\Config",
    "HKLM:\\Software\\Wow6432Node\\Microsoft\\Cryptography\\Wintrust\\Config"
)
foreach ($regPath in $wintrustPaths) {{
    if (-not (Test-Path $regPath)) {{
        New-Item -Path $regPath -Force | Out-Null
    }}
    New-ItemProperty -Path $regPath -Name "EnableCertPaddingCheck" -Value 1 -PropertyType DWord -Force | Out-Null
    Write-Host "  [OK] Da bat EnableCertPaddingCheck = 1 tai: $regPath" -ForegroundColor Green
}}

# ------------------------------------------------------------------------------
# [3/4] Khắc phục lỗ hổng MEDIUM: Chặn ICMP Timestamp Request/Reply (CVE-1999-0524)
# ------------------------------------------------------------------------------
Write-Host "`n[3/4] Tao Rule Windows Defender Firewall chan ICMPv4 Type 13 & 14..." -ForegroundColor Yellow
$ruleInName = "Nessus_AI_Block_ICMP_Timestamp_In"
$ruleOutName = "Nessus_AI_Block_ICMP_Timestamp_Out"

Remove-NetFirewallRule -DisplayName $ruleInName -ErrorAction SilentlyContinue
Remove-NetFirewallRule -DisplayName $ruleOutName -ErrorAction SilentlyContinue

New-NetFirewallRule -DisplayName $ruleInName `
    -Direction Inbound -Protocol ICMPv4 -IcmpType 13 `
    -Action Block -Profile Any -Enabled True | Out-Null

New-NetFirewallRule -DisplayName $ruleOutName `
    -Direction Outbound -Protocol ICMPv4 -IcmpType 14 `
    -Action Block -Profile Any -Enabled True | Out-Null

Write-Host "  [OK] Da kich hoat Firewall Rule chan ICMP Timestamp (Type 13/14)." -ForegroundColor Green

# ------------------------------------------------------------------------------
# [4/4] Khắc phục lỗ hổng MEDIUM: Bắt buộc ký số SMB (SMB Signing Required)
# ------------------------------------------------------------------------------
Write-Host "`n[4/4] Bat chinh sach bat buoc SMB Signing (RequireSecuritySignature = 1)..." -ForegroundColor Yellow
$smbPaths = @(
    "HKLM:\\SYSTEM\\CurrentControlSet\\Services\\LanmanServer\\Parameters",
    "HKLM:\\SYSTEM\\CurrentControlSet\\Services\\LanmanWorkstation\\Parameters"
)
foreach ($smbPath in $smbPaths) {{
    if (Test-Path $smbPath) {{
        Set-ItemProperty -Path $smbPath -Name "RequireSecuritySignature" -Value 1 -Type DWord -Force
        Set-ItemProperty -Path $smbPath -Name "EnableSecuritySignature" -Value 1 -Type DWord -Force
        Write-Host "  [OK] Da bat RequireSecuritySignature = 1 tai: $smbPath" -ForegroundColor Green
    }}
}}

# ------------------------------------------------------------------------------
# BƯỚC XÁC MINH TRẠNG THÁI SAU KHI VÁ (POST-REMEDIATION VERIFICATION)
# ------------------------------------------------------------------------------
Write-Host "`n================================================================" -ForegroundColor Cyan
Write-Host "  KET QUA KIEM CHUNG TRUC TIEP TREN HE THONG:" -ForegroundColor Cyan
Write-Host "================================================================" -ForegroundColor Cyan

$cert64 = (Get-ItemProperty -Path "HKLM:\\Software\\Microsoft\\Cryptography\\Wintrust\\Config" -Name "EnableCertPaddingCheck" -ErrorAction SilentlyContinue).EnableCertPaddingCheck
$smbSrv = (Get-ItemProperty -Path "HKLM:\\SYSTEM\\CurrentControlSet\\Services\\LanmanServer\\Parameters" -Name "RequireSecuritySignature" -ErrorAction SilentlyContinue).RequireSecuritySignature
$fwRule = Get-NetFirewallRule -DisplayName $ruleInName -ErrorAction SilentlyContinue

Write-Host "  1. WinVerifyTrust Padding Check (64-bit) : $cert64 (Mong doi: 1)"
Write-Host "  2. SMB Server RequireSecuritySignature   : $smbSrv (Mong doi: 1)"
Write-Host "  3. Firewall ICMP Type 13 Block Rule      : $($fwRule.Enabled) (Mong doi: True)"
Write-Host "`n[HOAN TAT] Vui long quay lai Dashboard de chay Validation Re-scan!" -ForegroundColor Green
"""


def generate_powershell_remediation_script(
    vulns_list: list[dict],
    target_ip: str = "192.168.104.129",
    use_ai: bool = True,
) -> str:
    """
    Sinh kịch bản PowerShell tổng hợp khắc phục danh sách lỗ hổng bằng AI
    kết hợp mẫu chuẩn thực nghiệm.
    """
    if not use_ai or not vulns_list:
        return build_standard_lab_remediation_ps1(target_ip)

    vulns_desc = []
    for idx, v in enumerate(vulns_list[:15], 1):
        vulns_desc.append(
            f"{idx}. [{v.get('severity_label', 'N/A')}] Plugin {v.get('plugin_id', '')}: "
            f"{v.get('plugin_name', '')} | CVE: {v.get('cve_list', 'N/A')} | "
            f"Port: {v.get('port', 0)} | Solution: {str(v.get('solution', ''))[:200]}"
        )
    vulns_text = "\n".join(vulns_desc)

    prompt = f"""Bạn là Chuyên gia Tự động hóa An toàn thông tin (SecOps / PowerShell Automation Engineer).
Hãy viết một file kịch bản PowerShell (.ps1) hoàn chỉnh, chạy dưới quyền Administrator trên máy mục tiêu Windows 11 ({target_ip}) để khắc phục triệt để danh sách lỗ hổng sau:

{vulns_text}

Yêu cầu bắt buộc trong script PowerShell:
1. Có `#Requires -RunAsAdministrator` ở đầu file.
2. Nếu danh sách có lỗi VLC Media Player, gỡ bỏ tự động VLC và dọn thư mục cài đặt.
3. Nếu có lỗi WinVerifyTrust (CVE-2013-3900), tạo và gán `EnableCertPaddingCheck = 1` (DWORD) cho cả nhánh 64-bit (`HKLM:\\Software\\Microsoft\\Cryptography\\Wintrust\\Config`) và 32-bit (`Wow6432Node`).
4. Nếu có lỗi ICMP Timestamp (CVE-1999-0524), dùng `New-NetFirewallRule` chặn ICMPv4 Type 13 (Inbound) và Type 14 (Outbound).
5. Nếu có lỗi SMB Signing, bật `RequireSecuritySignature = 1` cho `LanmanServer` và `LanmanWorkstation`.
6. Xử lý các lỗ hổng còn lại trong danh sách (nếu có) và in trạng thái kiểm tra xác minh (Verification) ở cuối script.
7. Chỉ trả về đúng nội dung code PowerShell (không bọc markdown ```powershell)."""

    try:
        raw = _call_llm(prompt).strip()
        if raw.startswith("```"):
            raw = raw.split("\n", 1)[1]
        if raw.endswith("```"):
            raw = raw.rsplit("```", 1)[0]
        return raw.strip()
    except Exception:
        return build_standard_lab_remediation_ps1(target_ip)


def ask_security_copilot(
    question: str,
    context_summary: str,
    chat_history: Optional[list[dict]] = None,
) -> str:
    """
    Interactive AI Security Copilot trả lời câu hỏi của người dùng dựa trên ngữ cảnh phiên quét.
    """
    history_text = ""
    if chat_history:
        recent = chat_history[-6:]
        history_text = "\n".join(
            [f"{'Người dùng' if m['role']=='user' else 'AI Copilot'}: {m['content']}" for m in recent]
        )

    prompt = f"""Bạn là **AI Security Copilot** tích hợp trong Hệ thống Quản lý & Phân tích Lỗ hổng Tenable Nessus (Phương án A).
Hạ tầng Lab thực nghiệm hiện tại:
- Máy Scanner (Host): 192.168.104.1 (Windows 11, chạy Nessus port 8834, Wireshark, AI Dashboard)
- Máy Mục tiêu (Target VM): 192.168.104.129 (Windows 11 Pro Build 26200)
- Máy Kiểm thử phụ: 192.168.104.132 (Kali Linux)
- Hạ tầng mạng ảo: VMware NAT VMnet8 (192.168.104.0/24, Gateway 192.168.104.254)

Ngữ cảnh dữ liệu phiên quét hiện tại:
{context_summary}

Lịch sử hội thoại gần đây:
{history_text}

Câu hỏi của quản trị viên: "{question}"

Hãy trả lời ngắn gọn, sắc bén, chuẩn thuật ngữ An toàn thông tin bằng Tiếng Việt, có dẫn chứng CVE / Plugin ID / lệnh PowerShell hoặc cơ chế kỹ thuật (SMB/Registry/Wireshark/Event Log) nếu liên quan."""

    return _call_llm(prompt)


def analyze_forensics_evidence(evidence_text: str, evidence_type: str = "Wireshark & Event Log") -> str:
    """
    Phân tích bằng chứng pháp chứng số (Wireshark SMB2/NTLMSSP & Windows Event Log 4624/4672)
    để chứng minh cơ chế hoạt động của Credentialed Scan (White-Box).
    """
    prompt = f"""Bạn là Chuyên gia Điều tra Số và Phân tích Pháp chứng Mạng (Digital Forensics & Incident Response - DFIR).
Dưới đây là dữ liệu bằng chứng thu thập được từ **{evidence_type}** trong quá trình Nessus Scanner (`192.168.104.1`) thực hiện quét có xác thực (Credentialed / White-Box Scan) vào máy mục tiêu Windows 11 (`192.168.104.129`):

{evidence_text}

Hãy phân tích chuyên sâu bằng tiếng Việt theo 4 mục:
1. **Giải mã luồng giao thức mạng (Wireshark Traffic Analysis)**: Giải thích quá trình bắt tay TCP port 445, thương lượng SMB2, xác thực NTLMSSP_AUTH và truy cập IPC$/ADMIN$/Remote Registry (`winreg`).
2. **Đối chiếu Nhật ký Sự kiện Windows (Event Viewer Correlation)**: Giải thích ý nghĩa của `Event ID 4624` (Logon Type 3 - Network Logon), `Event ID 4672` (Special Privileges Assigned) và tài khoản quản trị được Nessus sử dụng.
3. **Tại sao White-Box (Credentialed) lại vượt trội hơn Black-Box (Uncredentialed)**: Chứng minh vì sao nhờ phiên đăng nhập SMB/Registry này mà Nessus phát hiện được tới 47 mục (bao gồm VLC 2.2.0 Critical 9.8 và WinVerifyTrust High 8.8) trong khi quét ngoài mạng chỉ thấy 2 lỗi Medium.
4. **Khuyến nghị giám sát SOC (Detection & Hardening)**: Cách phân biệt lưu lượng quét hợp pháp của Nessus với hành vi Lateral Movement (Pass-the-Hash / SMB Exec) của kẻ tấn công."""

    return _call_llm(prompt)


def generate_comparison_ai_insight(summary: dict, mode: str = "Before vs After") -> str:
    """
    Nhận xét tự động của AI cho trang So sánh quét (Black-Box vs White-Box hoặc Before vs After).
    """
    prompt = f"""Bạn là Chuyên gia Đánh giá An toàn thông tin. Hãy phân tích kết quả đối chiếu 2 phiên quét Nessus theo chế độ **{mode}**:

- Số lượng lỗ hổng Phiên 1: {summary.get('total_before', 0)} (Phân bố: {json.dumps(summary.get('before_by_severity', {}), ensure_ascii=False)})
- Số lượng lỗ hổng Phiên 2: {summary.get('total_after', 0)} (Phân bố: {json.dumps(summary.get('after_by_severity', {}), ensure_ascii=False)})
- Đã triệt tiêu (Fixed): {summary.get('total_fixed', 0)}
- Phát hiện thêm (New): {summary.get('total_new', 0)}
- Còn tồn đọng (Remaining): {summary.get('total_remaining', 0)}
- Tỷ lệ khắc phục (Fix Rate): {summary.get('fix_rate_percent', 0)}%

Hãy viết nhận xét đánh giá 3 đoạn ngắn gọn bằng tiếng Việt:
1. Ý nghĩa thực nghiệm của sự thay đổi số liệu trên (nếu là Black-Box vs White-Box thì nhấn mạnh tầm quan trọng của Credentialed Scan qua SMB/Registry; nếu là Before vs After thì đánh giá hiệu quả của script PowerShell Auto-Remediation).
2. Đánh giá rủi ro đối với các lỗ hổng còn tồn đọng (nếu có).
3. Kết luận nghiệm thu an ninh (Security Closed-Loop)."""

    return _call_llm(prompt)


def analyze_nmap_scan_with_ai(command: str, raw_output: str, findings: list[dict] | None = None) -> str:
    """
    Phân tích kết quả quét Nmap/Nping thực tế bằng AI:
    - Giải thích bề mặt tấn công & chứng minh lỗ hổng từ log Nmap.
    - Mô tả kịch bản tấn công (Red Team) và sinh khuyến nghị + lệnh phòng thủ (Blue Team).
    """
    findings_text = ""
    if findings:
        findings_text = "\n".join(
            f"- [{f.get('verdict')}] {f.get('title')}: {f.get('evidence')} -> {f.get('attack_scenario')}"
            for f in findings
        )

    prompt = f"""Bạn là Chuyên gia Kiểm thử Xâm nhập (Penetration Tester) và Kỹ sư Phòng thủ Hệ thống (Blue Team Engineer).
Dưới đây là kết quả thực tế vừa thu thập được từ công cụ **Nmap / Nping**:

**Câu lệnh đã chạy:**
```bash
{command}
```

**Các phát hiện tự động từ Engine phân tích:**
{findings_text or "Xem trong log gốc bên dưới."}

**Output thực tế từ Nmap / Nping:**
```text
{raw_output[:5000]}
```

Hãy phân tích chi tiết bằng Tiếng Việt theo cấu trúc 4 phần rõ ràng:
1. **🎯 Chứng minh Lỗ hổng & Đánh giá Bề mặt Tấn công (Vulnerability Proof & Attack Surface)**:
   - Chỉ rõ những cổng (Port), dịch vụ (Service), hoặc cấu hình giao thức nào đang mở / bị lỗi dựa trên đúng các dòng log thực tế ở trên.
   - Đánh giá trạng thái an ninh hiện tại: Hạng mục nào đang **SAI (`FAIL ❌ - Có nguy cơ bị khai thác`)** và hạng mục nào đã **ĐÚNG (`PASS ✅ - Đã phòng thủ an toàn`)**.
2. **⚔️ Kịch bản Tấn công Thực tế (Attack Scenario - Red Team)**:
   - Với kết quả quét này, kẻ tấn công trong mạng LAN sẽ thực hiện những bước tấn công gì tiếp theo? (Ví dụ: SMB Relay / Man-in-the-Middle, thu thập thông tin RPC/NetBIOS, dò thời gian hệ thống ICMP Timestamp, Brute-force hoặc khai thác dịch vụ...).
3. **🛡️ Khuyến nghị & Lệnh Phòng thủ Cụ thể (Defense & Hardening - Blue Team)**:
   - Đưa ra các câu lệnh **PowerShell / Windows Defender Firewall (`New-NetFirewallRule`, `Set-SmbServerConfiguration`...)** chính xác để quản trị viên chạy trên máy mục tiêu nhằm vá các điểm yếu vừa phát hiện.
4. **✅ Tiêu chí Kiểm chứng Lại (Post-Defense Verification)**:
   - Nêu rõ sau khi chạy lệnh phòng thủ xong và quét lại cùng câu lệnh Nmap/Nping trên, dòng output nào sẽ thay đổi để chứng minh phòng thủ thành công (`FAIL ❌ -> PASS ✅`)."""

    return _call_llm(prompt)


