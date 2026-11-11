# TÀI LIỆU THIẾT KẾ & XÂY DỰNG HỆ THỐNG KIỂM THỬ TẤN CÔNG – XÁC THỰC PHÒNG THỦ TRỰC TIẾP
**Học phần:** Đảm bảo và An toàn Thông tin (Information Assurance and Security)  
**Định hướng mở rộng:** Tích hợp 2 công cụ chuẩn công nghiệp (**Nmap/Nping** & **WinVerifyTrust/VirusTotal**) tạo sự kiện kiểm chứng nhị phân **ĐÚNG (`PASS ✅`) / SAI (`FAIL ❌`)** trước và sau khi khắc phục lỗ hổng bằng AI.

---

## I. ĐẶT VẤN ĐỀ VÀ MỤC TIÊU TÍCH HỢP

Trong quy trình dò quét lỗ hổng truyền thống bằng **Tenable Nessus**, hệ thống chỉ dừng lại ở mức phát hiện dấu hiệu (dựa trên banner dịch vụ, phiên bản phần mềm hoặc giá trị khóa Registry) và xuất báo cáo tĩnh. Quá trình quét lại (Re-scan) của Nessus mất từ 5–10 phút và không trực tiếp cho thấy **cơ chế phòng thủ của hệ điều hành đã thực sự chặn đứng hành vi khai thác như thế nào**.

Để giải quyết triệt để bài toán chứng minh tính **Đúng / Sai (True / False)** trong Bảo đảm An toàn Thông tin, hệ thống được mở rộng thêm phân hệ **Live Attack/Defense Verifier** gồm **2 công cụ thực chiến** chia nhau kiểm định 2 tầng bảo mật của máy mục tiêu (`192.168.104.129`):

| Công cụ tích hợp | Tầng phụ trách | Lỗ hổng mục tiêu từ Nessus | Căn cứ Giáo trình BĐATTT | Kết quả Sự kiện Đúng / Sai |
| :--- | :--- | :--- | :--- | :--- |
| **Công cụ 1: Nmap NSE + Nping** | **Tầng Mạng (Network Layer)** | • `Plugin 10114`: ICMP Timestamp (`CVE-1999-0524`)<br>• `Plugin 57608`: SMB Signing not required | • **Bài 6 & Bài 7**: Tường lửa Windows (`netsh advfirewall`)<br>• **Bài 13**: Trinh sát mạng & Tấn công MITM / Replay | • **SAI (`FAIL ❌`)**: Nhận được gói ICMP Type 14 / Cho phép SMB không ký số.<br>• **ĐÚNG (`PASS ✅`)**: Firewall chặn gói tin (100% loss) / Bắt buộc ký số SMB. |
| **Công cụ 2: WinVerifyTrust + SHA-256 / VirusTotal** | **Tầng Tập tin & Host (Host/File Layer)** | • `Plugin 166555`: WinVerifyTrust (`CVE-2013-3900`)<br>• `Plugin 81817`: VLC Media Player 2.2.0 (`CVSS 9.8`) | • **Bài 8**: Hàm băm mật mã (`MD5/SHA-256`) & Chữ ký số<br>• **Bài 11 & 12**: Chèn dữ liệu cuối file PE, Phân tích tĩnh & **VirusTotal** | • **SAI (`FAIL ❌`)**: File bị sửa đổi (lệch Hash SHA-256) nhưng chữ ký số vẫn báo `Valid`.<br>• **ĐÚNG (`PASS ✅`)**: Windows phát hiện `HashMismatch` và chặn thực thi. |

---

## II. KIẾN TRÚC PHỐI HỢP LIÊN HOÀN 4 CÔNG CỤ

1. **Tenable Nessus Scanner (`192.168.104.1`)**: Quét White-Box máy mục tiêu `192.168.104.129` $\rightarrow$ Phát hiện 47 bản ghi và tách thành 2 mặt trận lỗ hổng (Mặt trận Mạng & Mặt trận Tập tin/Host).
2. **Công cụ 1 (`Nmap NSE + Nping`) & Công cụ 2 (`WinVerifyTrust + VirusTotal`) — Lần chạy 1 (Trước khi vá)**:
   - Thực hiện kiểm thử trực tiếp lên mục tiêu $\rightarrow$ Ghi nhận sự kiện **PHÒNG THỦ = SAI (`VULNERABLE ❌`)**.
3. **AI Auto-Remediation Engine**:
   - Sinh và thực thi kịch bản PowerShell (`.ps1`) cấu hình Firewall, Registry và gỡ bỏ phần mềm lỗi thời.
4. **Công cụ 1 & Công cụ 2 — Lần chạy 2 (Sau khi vá - 3 giây)**:
   - Chạy lại phép thử $\rightarrow$ Ghi nhận sự kiện **PHÒNG THỦ = ĐÚNG (`PROTECTED ✅`)**.

---

## III. THIẾT KẾ CHI TIẾT CÔNG CỤ 1: BỘ KIỂM THỬ MẠNG (`NMAP NSE` & `NPING`)

### 1. Phép thử 1A: Kiểm thử rò rỉ thời gian hệ thống qua `ICMP Timestamp (Type 13/14)`
* **Lệnh thực thi**:
  ```powershell
  nping --icmp --icmp-type 13 -c 2 192.168.104.129
  ```
* **Logic phân định ĐÚNG / SAI**:
  * **Sự kiện SAI (`PHÒNG THỦ THẤT BẠI ❌`)**: Nhận được phản hồi `Timestamp reply (type=14/code=0)` chứa thời gian hệ thống.
  * **Sự kiện ĐÚNG (`PHÒNG THỦ THÀNH CÔNG ✅`)**: `Lost: 2 (100.00%)` — Tường lửa đã chặn đứng gói tin ICMP Type 13/14.

### 2. Phép thử 1B: Kiểm thử bắt buộc ký số giao thức SMB (`SMB2 Security Mode`)
* **Lệnh thực thi**:
  ```powershell
  nmap -p 445 --script smb2-security-mode 192.168.104.129
  ```
* **Logic phân định ĐÚNG / SAI**:
  * **Sự kiện SAI (`PHÒNG THỦ THẤT BẠI ❌`)**: `Message signing enabled but not required`.
  * **Sự kiện ĐÚNG (`PHÒNG THỦ THÀNH CÔNG ✅`)**: `Message signing enabled and required`.

---

## IV. THIẾT KẾ CHI TIẾT CÔNG CỤ 2: BỘ KIỂM ĐỊNH CHỮ KÝ SỐ (`WINVERIFYTRUST`) & PHÂN TÍCH TĨNH (`SHA-256 / VIRUSTOTAL`)

### 1. Kỹ thuật tạo File Kiểm thử Đệm Chứng chỉ An toàn (`CVE-2013-3900`)
1. Sao chép một file thực thi có chữ ký số hợp lệ của Microsoft (ví dụ `C:\Windows\System32\notepad.exe` hoặc `calc.exe`).
2. Đọc cấu trúc PE Header để tìm vị trí bảng chứng chỉ `Certificate Table` (`IMAGE_DIRECTORY_ENTRY_SECURITY`).
3. Chèn thêm 16 byte đệm vô hại (`b"NESSUS_AI_TEST00"`) vào cuối vùng chứng chỉ và cập nhật kích thước `dwLength`.
4. Tính toán mã băm `MD5`, `SHA-1`, `SHA-256` của file gốc và file đã chèn padding, đồng thời đối chiếu qua **VirusTotal API v3**.
5. Gọi `Get-AuthenticodeSignature` (`WinVerifyTrust`) để kiểm tra chữ ký số của file đã bị chèn byte:
   - **Khi `EnableCertPaddingCheck = 0` (Chưa vá)**: Trả về `Status = Valid` $\rightarrow$ **PHÒNG THỦ: SAI ❌** (Dù mã băm SHA-256 đã thay đổi nhưng chữ ký số vẫn bị qua mặt!).
   - **Khi `EnableCertPaddingCheck = 1` (Đã vá)**: Trả về `Status = HashMismatch` $\rightarrow$ **PHÒNG THỦ: ĐÚNG ✅** (Hệ điều hành phát hiện ngay hành vi chèn dữ liệu cuối file!).

---

## V. CẤU TRÚC MODULE TÍCH HỢP VÀO DỰ ÁN

1. **`utils/live_verifier.py`**: Chứa toàn bộ hàm gọi `Nmap/Nping`, tạo file kiểm thử PE Padding an toàn, kiểm tra `WinVerifyTrust`, tính `MD5/SHA-1/SHA-256` và tra cứu `VirusTotal API`.
2. **Menu `⚔️ Kiểm thử Tấn công & Phòng thủ` trong `app.py`**: Giao diện trực quan bấm nút chạy kiểm thử Lần 1 (Trước vá) và Lần 2 (Sau vá), hiển thị bảng so sánh trạng thái **SAI (`FAIL ❌`) $\rightarrow$ ĐÚNG (`PASS ✅`)** và nút tải **Script Khôi phục trạng thái lỗi (`Rollback.ps1`)** để phục vụ demo nhiều lần.
