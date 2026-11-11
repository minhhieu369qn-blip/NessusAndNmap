"""
app.py - Giao diện chính Streamlit cho Nessus AI Analyzer.

Chạy:  streamlit run app.py
"""

import streamlit as st
import pandas as pd
import plotly.express as px
import plotly.graph_objects as go
from pathlib import Path
import json
import sys
import os
import time

# Đảm bảo import được các module
sys.path.insert(0, str(Path(__file__).resolve().parent))

from config import Settings
from database.connection import test_connection
from parsers.nessus_parser import parse_file, SEVERITY_MAP

# ═══════════════════════════════════════════════════════════
#  PAGE CONFIG & SESSION STATE
# ═══════════════════════════════════════════════════════════

st.set_page_config(
    page_title="🛡️ Nessus AI Analyzer",
    page_icon="🛡️",
    layout="wide",
    initial_sidebar_state="expanded",
)

# Giao diện Sáng (Nền Trắng - Chữ Đen rõ nét)
st.markdown(
    """
    <style>
    /* Nền chính trắng tinh, chữ đen đậm rõ ràng */
    .stApp, [data-testid="stAppViewContainer"], [data-testid="stHeader"] {
        background-color: #ffffff !important;
        color: #0f172a !important;
    }
    /* Sidebar nền xám trắng thanh lịch, viền rõ */
    [data-testid="stSidebar"] {
        background-color: #f8fafc !important;
        border-right: 1px solid #cbd5e1 !important;
    }
    [data-testid="stSidebar"] * {
        color: #0f172a !important;
    }
    /* Toàn bộ tiêu đề, đoạn văn, nhãn, metric chữ đen đậm */
    h1, h2, h3, h4, h5, h6, p, li, span, label, div[data-testid="stMarkdownContainer"] {
        color: #0f172a;
    }
    [data-testid="stMetricValue"] {
        color: #0f172a !important;
        font-weight: 700 !important;
    }
    [data-testid="stMetricLabel"] {
        color: #334155 !important;
        font-weight: 600 !important;
    }
    /* Khung Expander & Card rõ nét trên nền trắng */
    [data-testid="stExpander"] {
        background-color: #ffffff !important;
        border: 1px solid #cbd5e1 !important;
        border-radius: 8px !important;
    }
    /* Ô nhập liệu (Input, Selectbox, Textarea) nền trắng viền đậm dễ nhìn */
    input, textarea, [data-baseweb="select"] > div {
        background-color: #ffffff !important;
        color: #0f172a !important;
        border-color: #94a3b8 !important;
    }
    /* Khung code terminal sáng rõ */
    pre, code {
        background-color: #f1f5f9 !important;
        color: #0f172a !important;
        border: 1px solid #cbd5e1 !important;
    }
    </style>
    """,
    unsafe_allow_html=True,
)

# Khởi tạo session state
if "db_connected" not in st.session_state:
    try:
        ok_db, msg_db = test_connection()
        st.session_state.db_connected = ok_db
        st.session_state.db_message = msg_db
    except Exception as e:
        st.session_state.db_connected = False
        st.session_state.db_message = str(e)
if "ai_connected" not in st.session_state:
    # Tự động kiểm tra AI khi khởi động nếu có API key
    if Settings.get_active_api_key():
        try:
            from ai_engine.analyzer import test_ai_connection
            ok_ai, msg_ai = test_ai_connection()
            st.session_state.ai_connected = ok_ai
            st.session_state.ai_message = msg_ai
        except Exception as e:
            st.session_state.ai_connected = False
            st.session_state.ai_message = str(e)
    else:
        st.session_state.ai_connected = False
if "parsed_data" not in st.session_state:
    st.session_state.parsed_data = None
if "current_session_id" not in st.session_state:
    st.session_state.current_session_id = None
if "copilot_messages" not in st.session_state:
    st.session_state.copilot_messages = []


# ═══════════════════════════════════════════════════════════
#  HELPER FUNCTIONS
# ═══════════════════════════════════════════════════════════

def ensure_vuln_df(df: pd.DataFrame) -> pd.DataFrame:
    """Đảm bảo DataFrame lỗ hổng luôn có đủ các cột cơ bản để tránh KeyError."""
    standard_cols = [
        "host_ip", "host_name", "port", "protocol", "service_name",
        "plugin_id", "plugin_name", "plugin_family", "severity",
        "severity_label", "cvss_base_score", "cvss3_base_score",
        "cve_list", "synopsis", "description", "solution",
        "plugin_output", "see_also", "exploit_available"
    ]
    if df is None or df.empty:
        return pd.DataFrame(columns=standard_cols)
    df_out = df.copy()
    for col in standard_cols:
        if col not in df_out.columns:
            if col == "severity":
                df_out[col] = 0
            elif col == "severity_label":
                df_out[col] = "Info"
            elif col in ("port", "plugin_id"):
                df_out[col] = 0
            elif col == "exploit_available":
                df_out[col] = False
            else:
                df_out[col] = ""
    df_out["severity"] = pd.to_numeric(df_out["severity"], errors="coerce").fillna(0).astype(int)
    df_out["severity_label"] = df_out["severity"].map(SEVERITY_MAP).fillna("Info")
    return df_out

SEVERITY_COLORS = {
    "Critical": "#9B1D20",
    "High": "#D84315",
    "Medium": "#F9A825",
    "Low": "#2E7D32",
    "Info": "#1565C0",
}


def check_connections():
    """Tải lại .env và kiểm tra kết nối DB và AI."""
    from dotenv import load_dotenv
    load_dotenv(Path(__file__).resolve().parent / ".env", override=True)
    Settings.AI_PROVIDER = os.getenv("AI_PROVIDER", "gemini").lower()
    Settings.GEMINI_API_KEY = os.getenv("GEMINI_API_KEY", "")
    Settings.OPENAI_API_KEY = os.getenv("OPENAI_API_KEY", "")
    Settings.AI_MODEL = os.getenv("AI_MODEL", "")
    Settings.DB_SERVER = os.getenv("DB_SERVER", "localhost")
    Settings.DB_NAME = os.getenv("DB_NAME", "NessusAnalyzer")

    # DB
    ok, msg = test_connection()
    st.session_state.db_connected = ok
    st.session_state.db_message = msg

    # AI
    from ai_engine.analyzer import test_ai_connection
    ok_ai, msg_ai = test_ai_connection()
    st.session_state.ai_connected = ok_ai
    st.session_state.ai_message = msg_ai


def severity_badge(label: str) -> str:
    """Trả về HTML badge cho mức severity."""
    color = SEVERITY_COLORS.get(label, "#666")
    return f'<span style="background-color:{color};color:white;padding:2px 10px;border-radius:4px;font-weight:bold;font-size:0.85em">{label}</span>'


def clear_web_session_state():
    """Đưa toàn bộ trạng thái phân tích tạm trên Web về mặc định (0 dữ liệu đầu vào)."""
    keys_to_clear = [
        "parsed_data",
        "current_session_id",
        "last_analysis",
        "last_scan_summary",
        "generated_ps1",
        "copilot_messages",
        "forensic_ai_report",
        "nessus_scans",
        "nessus_client",
        "nmap_history",
        "nping_last",
        "nmap_results",
    ]
    for k in keys_to_clear:
        if k in st.session_state:
            if k == "copilot_messages":
                st.session_state[k] = []
            elif k in ("nmap_history", "nmap_results"):
                st.session_state[k] = [] if k == "nmap_history" else {}
            else:
                st.session_state[k] = None


# ═══════════════════════════════════════════════════════════
#  SIDEBAR
# ═══════════════════════════════════════════════════════════

with st.sidebar:
    st.image("https://img.icons8.com/fluency/96/security-checked.png", width=60)
    st.title("Nessus AI Analyzer")
    st.caption("Hệ sinh thái Phân tích Lỗ hổng & Kiểm chứng An toàn bằng AI & Nmap (Phương án A)")
    st.divider()

    menu = st.radio(
        "📋 Chức năng",
        [
            "🏠 Tổng quan",
            "📤 Import Báo cáo",
            "🔍 Phân tích AI",
            "🛰️ Công cụ Nmap",
            "📊 Dashboard",
            "🔄 So sánh quét",
            "🔬 Bằng chứng Forensics",
            "📋 Quản lý khắc phục",
            "⚙️ Cài đặt",
        ],
        label_visibility="collapsed",
    )

    st.divider()

    # Trạng thái kết nối
    st.subheader("🔌 Trạng thái")

    if st.button("🔄 Kiểm tra kết nối", use_container_width=True):
        with st.spinner("Đang kiểm tra..."):
            check_connections()

    import importlib
    import utils.nmap_verifier
    importlib.reload(utils.nmap_verifier)
    from utils.nmap_verifier import detect_nmap_environment
    nmap_env = detect_nmap_environment()

    col1, col2, col3 = st.columns(3)
    with col1:
        if st.session_state.db_connected:
            st.success("DB ✅")
        else:
            st.error("DB ❌")
    with col2:
        if st.session_state.ai_connected:
            st.success("AI ✅")
        else:
            st.warning("AI ⚠️")
    with col3:
        if nmap_env["available"]:
            st.success("Nmap ✅")
        else:
            st.error("Nmap ❌")

    st.divider()
    st.subheader("🧹 Làm mới Phiên")
    if st.button("🧹 Làm mới bộ nhớ Web", use_container_width=True, help="Xóa dữ liệu phân tích tạm & lịch sử chat trên Web (Giữ nguyên Database)"):
        clear_web_session_state()
        st.toast("✅ Đã làm mới toàn bộ trạng thái phân tích tạm trên Web!")
        time.sleep(0.5)
        st.rerun()

    with st.expander("🗑️ Reset toàn bộ về 0"):
        st.caption("Đưa cả Web và SQL Server về trạng thái ban đầu (0 phiên quét, 0 lỗ hổng).")
        confirm_reset = st.checkbox("Tôi xác nhận xóa sạch dữ liệu", key="confirm_full_reset")
        if st.button(
            "🔥 Xóa trắng toàn bộ về 0",
            type="primary",
            disabled=not confirm_reset,
            use_container_width=True,
        ):
            try:
                from database.crud import reset_all_database_data
                if st.session_state.db_connected:
                    reset_all_database_data()
                clear_web_session_state()
                st.success("✅ Đã đưa toàn bộ hệ thống về 0!")
                time.sleep(0.8)
                st.rerun()
            except Exception as e:
                st.error(f"❌ Lỗi khi reset: {e}")


# ═══════════════════════════════════════════════════════════
#  PAGE: TỔNG QUAN
# ═══════════════════════════════════════════════════════════

if menu == "🏠 Tổng quan":
    st.header("🏠 Tổng quan Hệ sinh thái Kiểm thử & Khắc phục Lỗ hổng bằng AI")
    st.markdown("""
    **Nessus AI Analyzer (Phương án A)** là nền tảng quản lý vòng đời lỗ hổng bảo mật khép kín (**Closed-Loop Vulnerability Management**), tích hợp trực tiếp với **Tenable Nessus** và **Trí tuệ Nhân tạo (LLM)**.
    """)

    st.divider()

    # Thống kê nhanh nếu đã kết nối DB
    if st.session_state.db_connected:
        try:
            from database.crud import get_all_scan_sessions, get_vulnerabilities_by_session
            sessions = get_all_scan_sessions()

            c1, c2, c3 = st.columns(3)
            c1.metric("📁 Phiên quét trong DB", len(sessions))
            c2.metric("🖥️ Tổng lượt Host quét", int(sessions["total_hosts"].sum()) if not sessions.empty else 0)
            c3.metric("🐛 Tổng bản ghi Lỗ hổng", int(sessions["total_vulns"].sum()) if not sessions.empty else 0)

            if not sessions.empty:
                st.subheader("📁 Danh sách phiên quét đã lưu")
                st.dataframe(
                    sessions[["id", "scan_name", "import_date", "file_type", "total_hosts", "total_vulns", "notes"]].head(15),
                    use_container_width=True,
                    hide_index=True,
                )

                # Chỉ hiển thị danh sách Host & Sơ đồ mạng khi ĐÃ CÓ dữ liệu phiên quét thực tế
                latest_sid = int(sessions.iloc[0]["id"])
                df_latest = get_vulnerabilities_by_session(latest_sid)
                if not df_latest.empty and "host_ip" in df_latest.columns:
                    st.subheader(f"🗺️ Danh sách Máy mục tiêu trong Phiên quét gần nhất (#{latest_sid})")
                    host_summary = (
                        df_latest.groupby(["host_ip", "host_name"], dropna=False)
                        .agg(
                            total_records=("plugin_id", "count"),
                            max_severity=("severity", "max"),
                            open_ports=("port", lambda s: ", ".join(sorted({str(p) for p in s if pd.notna(p) and int(p) > 0})) or "ICMP/Local"),
                        )
                        .reset_index()
                    )
                    host_summary["Mức rủi ro cao nhất"] = host_summary["max_severity"].map(SEVERITY_MAP).fillna("Info")
                    st.dataframe(
                        host_summary[["host_ip", "host_name", "Mức rủi ro cao nhất", "total_records", "open_ports"]].rename(
                            columns={
                                "host_ip": "Địa chỉ IP",
                                "host_name": "Tên Host",
                                "total_records": "Số bản ghi phát hiện",
                                "open_ports": "Các cổng dịch vụ ghi nhận",
                            }
                        ),
                        use_container_width=True,
                        hide_index=True,
                    )

                with st.expander("🗑️ Xóa lẻ phiên quét bị trùng / không cần thiết"):
                    del_col1, del_col2 = st.columns([3, 1])
                    with del_col1:
                        del_sid = st.selectbox(
                            "Chọn phiên quét cần xóa",
                            sessions["id"].tolist(),
                            format_func=lambda x: f"#{x} - {sessions[sessions['id']==x]['scan_name'].values[0]}",
                            key="del_session_select",
                        )
                    with del_col2:
                        st.write("")
                        st.write("")
                        if st.button("🗑️ Xóa phiên này", use_container_width=True):
                            from database.crud import delete_scan_session
                            delete_scan_session(int(del_sid))
                            st.success(f"✅ Đã xóa phiên quét #{del_sid}!")
                            time.sleep(0.6)
                            st.rerun()
            else:
                st.info("📭 **Hiện chưa có dữ liệu phiên quét nào trong hệ thống (Trạng thái = 0).** Hãy xem hướng dẫn bên dưới và vào mục **📤 Import Báo cáo** để bắt đầu.")
        except Exception as e:
            st.info(f"💡 Nhấn **Kiểm tra kết nối** ở sidebar để bắt đầu. ({e})")
    else:
        st.info(
            "💡 Hãy cấu hình kết nối trong file `.env` và nhấn **Kiểm tra kết nối** ở sidebar.\n\n"
            "Nếu chưa tạo database, chạy: `python setup_db.py`"
        )

    st.divider()

    # ── MỤC HƯỚNG DẪN SỬ DỤNG CHI TIẾT ──
    st.subheader("📖 Hướng dẫn sử dụng Hệ thống (Quy trình Khép kín 5 Bước)")

    g_col1, g_col2 = st.columns(2)

    with g_col1:
        with st.expander("📤 Bước 1: Nạp dữ liệu quét từ Nessus (Import Báo cáo)", expanded=True):
            st.markdown("""
            Truy cập menu **📤 Import Báo cáo** ở thanh bên trái, chọn 1 trong 2 cách:
            - **Cách 1 (Upload File)**: Tải lên file `.nessus` (XML) hoặc `.csv` xuất từ Tenable Nessus $\rightarrow$ nhấn **💾 Lưu vào Database**.
            - **Cách 2 (Kết nối trực tiếp Nessus Local API)**:
              1. Nhập tài khoản Nessus (`https://localhost:8834`) hoặc cặp khóa `Access Key / Secret Key`.
              2. Nhấn **🔌 Kết nối Nessus & Lấy danh sách Scans**.
              3. Chọn phiên quét cần lấy (ví dụ: *Host Discovery*, *Black-Box*, *White-Box*) $\rightarrow$ nhấn **📥 Nạp toàn bộ kết quả quét** để tự động lưu vào SQL Server.
            """)

        with st.expander(" 📊 Bước 2: Quan sát Ma trận Rủi ro (Dashboard)", expanded=True):
            st.markdown("""
            Truy cập menu **📊 Dashboard**:
            - Chọn phiên quét đã lưu trong Database.
            - Sử dụng **Bộ lọc đa chiều** để lọc nhanh theo **CVE**, **Host IP**, **Cổng dịch vụ (Port)** hoặc **Mức độ nghiêm trọng (Critical, High, Medium, Low, Info)**.
            - Quan sát **Biểu đồ phân bổ lỗ hổng**, **Ma trận tương quan rủi ro (CVSS v3.0 vs. VPR)** và bảng **Cảnh báo lỗ hổng đã có mã khai thác (Exploit Available)**.
            """)

        with st.expander("🔍 Bước 3: Phân tích AI, Sinh Script PowerShell & Hỏi đáp Copilot", expanded=True):
            st.markdown("""
            Truy cập menu **🔍 Phân tích AI** (gồm 3 tab chức năng):
            1. **Phân tích Lỗ hổng & Báo cáo Quản trị**: Chọn từng lỗ hổng để AI giải thích *Nguyên nhân gốc rễ, Rủi ro CIA, Các bước khắc phục, Lệnh xác minh* hoặc bấm **📑 AI Tóm tắt Báo cáo Quản trị** cho toàn bộ phiên quét.
            2. **⚡ Auto-Remediation (Sinh Script `.ps1`)**: Tự động sinh kịch bản PowerShell `.ps1` để tải về chạy dưới quyền Administrator trên máy mục tiêu, khắc phục triệt để các lỗ hổng (VLC, WinVerifyTrust `CVE-2013-3900`, Firewall chặn ICMP Timestamp, bật SMB Signing).
            3. **💬 AI Security Copilot**: Trò chuyện, đặt câu hỏi trực tiếp bằng Tiếng Việt với trợ lý AI về kết quả quét hiện tại.
            """)

    with g_col2:
        with st.expander("🛰️ Bước 4: Kiểm chứng Chủ động bằng Công cụ Nmap & Nping", expanded=True):
            st.markdown("""
            Truy cập menu **🛰️ Công cụ Nmap**:
            - **Quét mạng đa năng (Nmap Scan)**: Quét cổng, nhận diện dịch vụ/phiên bản (`-sV`), hệ điều hành (`-O`), hoặc chạy 600+ script NSE (như `smb2-security-mode`, `vuln`, `ssl-enum-ciphers`...) tới bất kỳ IP/mục tiêu nào.
            - **Bắn gói tin thăm dò (Nping)**: Gửi gói ICMP tùy chọn (Type 8 Ping, Type 13 Timestamp...) hoặc TCP/UDP cờ tùy biến để kiểm tra phản hồi thực tế từ tường lửa.
            - **Đối chiếu & So sánh (Lịch sử Nmap)**: Tự động lưu lịch sử từng lần quét, so sánh chênh lệch trạng thái cổng/script giữa các lần chạy (trước và sau vá), hoặc đối chiếu với dữ liệu Nessus trong Database.
            """)

        with st.expander("🔄 Bước 5: Đối chiếu Đa kịch bản (So sánh quét) & Pháp chứng Forensics", expanded=True):
            st.markdown("""
            - **Menu 🔄 So sánh quét**:
              - Đối chiếu **🕵️ Black-Box vs. White-Box** hoặc **🔧 Before Patch vs. After Patch** để tính tỷ lệ vá lỗi (**Fix Rate %**) và xuất **🏆 Chứng nhận Nghiệm thu An toàn (`.html`)**.
            - **Menu 🔬 Bằng chứng Forensics & 📋 Quản lý khắc phục**:
              - Tải lên file `.csv` từ **Wireshark** và **Windows Event Viewer** để AI phân tích tương quan pháp chứng (DFIR), cập nhật tiến độ xử lý lỗ hổng.
            - **Làm mới khi cần**: Dùng nút **🧹 Làm mới bộ nhớ Web** hoặc **🗑️ Reset toàn bộ về 0** ở góc dưới menu trái để đưa hệ thống về trạng thái trắng ban đầu.
            """)




# ═══════════════════════════════════════════════════════════
#  PAGE: IMPORT BÁO CÁO
# ═══════════════════════════════════════════════════════════

elif menu == "📤 Import Báo cáo":
    st.header("📤 Import Báo cáo Nessus")

    import_method = st.radio(
        "Chọn phương thức import",
        ["📁 Upload file (.nessus / .csv)", "🔌 Kết nối trực tiếp qua Nessus Local API"],
        horizontal=True,
    )

    # ─────────────────────────────────────────────────────────
    #  PHƯƠNG THỨC 1: UPLOAD FILE
    # ─────────────────────────────────────────────────────────
    if import_method.startswith("📁"):
        uploaded = st.file_uploader(
            "Chọn file báo cáo Nessus",
            type=["nessus", "csv"],
            help="Hỗ trợ file .nessus (XML) và .csv xuất từ Nessus",
        )

    if uploaded:
        with st.spinner(f"🔄 Đang phân tích file `{uploaded.name}`..."):
            try:
                content = uploaded.read()
                result = parse_file(content, uploaded.name)

                df_vulns = ensure_vuln_df(result.get("vulnerabilities"))
                result["vulnerabilities"] = df_vulns
                st.session_state.parsed_data = result
                meta = result.get("metadata", {})

                st.success(f"✅ Đã phân tích thành công file `{uploaded.name}`!")

                # Hiển thị metadata
                st.subheader("📋 Thông tin quét")
                mc1, mc2, mc3, mc4 = st.columns(4)
                mc1.metric("🏷️ Tên quét", str(meta.get("scan_name", ""))[:40])
                mc2.metric("🖥️ Số host", meta.get("total_hosts", 0))
                mc3.metric("🐛 Tổng lỗ hổng", meta.get("total_vulns", 0))
                mc4.metric("📄 Loại file", str(meta.get("file_type", "")).upper())

                if not df_vulns.empty:
                    # Thống kê severity
                    st.subheader("📊 Phân bổ mức nghiêm trọng")
                    sev_counts = df_vulns["severity_label"].value_counts()

                    cols = st.columns(5)
                    for i, sev in enumerate(["Critical", "High", "Medium", "Low", "Info"]):
                        count = sev_counts.get(sev, 0)
                        cols[i].metric(
                            f"{sev}",
                            count,
                            delta=None,
                        )

                    # Biểu đồ
                    fig = px.pie(
                        names=sev_counts.index,
                        values=sev_counts.values,
                        color=sev_counts.index,
                        color_discrete_map=SEVERITY_COLORS,
                        title="Phân bổ lỗ hổng theo mức nghiêm trọng",
                    )
                    st.plotly_chart(fig, use_container_width=True)

                    # Bảng dữ liệu
                    st.subheader("📝 Danh sách lỗ hổng")
                    display_cols = [
                        c for c in ["host_ip", "port", "plugin_id", "plugin_name",
                                     "severity_label", "cvss3_base_score", "cve_list"]
                        if c in df_vulns.columns
                    ]
                    sorted_vulns = df_vulns.sort_values("severity", ascending=False)
                    st.dataframe(
                        sorted_vulns[display_cols] if display_cols else sorted_vulns,
                        use_container_width=True,
                        hide_index=True,
                        height=400,
                    )

                    # Nút lưu vào DB
                    st.divider()
                    if st.session_state.db_connected:
                        scan_name_input = st.text_input(
                            "Tên phiên quét (để lưu vào DB)",
                            value=meta["scan_name"],
                        )
                        notes_input = st.text_area("Ghi chú (tùy chọn)", height=80)

                        if st.button("💾 Lưu vào Database", type="primary", use_container_width=True):
                            with st.spinner("Đang lưu..."):
                                try:
                                    from database.crud import insert_scan_session, insert_vulnerabilities_bulk

                                    session_id = insert_scan_session(
                                        scan_name=scan_name_input,
                                        source_file=uploaded.name,
                                        file_type=meta["file_type"],
                                        scan_date=meta.get("scan_date"),
                                        scanner_name=meta.get("scanner_name"),
                                        policy_name=meta.get("policy_name"),
                                        total_hosts=meta["total_hosts"],
                                        total_vulns=meta["total_vulns"],
                                        notes=notes_input or None,
                                    )

                                    inserted = insert_vulnerabilities_bulk(session_id, df_vulns)
                                    st.session_state.current_session_id = session_id

                                    st.success(
                                        f"✅ Đã lưu phiên quét #{session_id} với {inserted} lỗ hổng vào database!"
                                    )
                                except Exception as e:
                                    st.error(f"❌ Lỗi khi lưu vào DB: {e}")
                    else:
                        st.warning("⚠️ Chưa kết nối database. Hãy cấu hình và kiểm tra kết nối trước khi lưu.")

            except Exception as e:
                st.error(f"❌ Lỗi khi phân tích file: {e}")

    # ─────────────────────────────────────────────────────────
    #  PHƯƠNG THỨC 2: NESSUS LOCAL API
    # ─────────────────────────────────────────────────────────
    else:
        from parsers.nessus_api import NessusAPIClient

        st.markdown("""
        > 💡 **Dành cho Nessus Essentials** — phiên bản miễn phí không cho phép xuất file báo cáo.
        > Kết nối trực tiếp qua API để lấy toàn bộ kết quả quét.
        """)

        st.subheader("🔑 Xác thực Nessus")

        auth_method = st.radio(
            "Phương thức xác thực",
            ["👤 Username / Password", "🔑 API Keys (Access Key + Secret Key)"],
            horizontal=True,
            help="API Keys ổn định hơn, lấy tại: Nessus → Settings → My Account → API Keys → Generate",
        )

        # Nessus URL
        nessus_url = st.text_input(
            "🌐 Nessus URL",
            value=Settings.NESSUS_URL or "https://localhost:8834",
            help="URL của Nessus Scanner (mặc định: https://localhost:8834)",
        )

        nessus_user = ""
        nessus_pass = ""
        nessus_access = ""
        nessus_secret = ""

        if auth_method.startswith("👤"):
            col_u, col_p = st.columns(2)
            with col_u:
                nessus_user = st.text_input(
                    "👤 Username",
                    value=Settings.NESSUS_USERNAME,
                    placeholder="admin",
                )
            with col_p:
                nessus_pass = st.text_input(
                    "🔒 Password",
                    type="password",
                    value=Settings.NESSUS_PASSWORD,
                )
        else:
            col_ak, col_sk = st.columns(2)
            with col_ak:
                nessus_access = st.text_input(
                    "🔑 Access Key",
                    value=Settings.NESSUS_ACCESS_KEY,
                    type="password",
                    placeholder="abcdef1234567890...",
                )
            with col_sk:
                nessus_secret = st.text_input(
                    "🗝️ Secret Key",
                    value=Settings.NESSUS_SECRET_KEY,
                    type="password",
                    placeholder="abcdef1234567890...",
                )

        st.divider()

        # ── Bước 1: Kết nối & lấy danh sách scan ──
        if st.button("🔌 Kết nối Nessus & Lấy danh sách Scans", type="primary", use_container_width=True):
            client = NessusAPIClient(
                url=nessus_url,
                username=nessus_user,
                password=nessus_pass,
                access_key=nessus_access,
                secret_key=nessus_secret,
            )

            with st.spinner("🔄 Đang kết nối đến Nessus..."):
                ok, msg = client.login()

            if ok:
                st.success(msg)

                # Lấy danh sách scans
                with st.spinner("📋 Đang tải danh sách scans..."):
                    try:
                        scans = client.list_scans()
                        st.session_state.nessus_client = client
                        st.session_state.nessus_scans = scans
                    except Exception as e:
                        st.error(f"❌ Lỗi khi lấy danh sách scans: {e}")
            else:
                st.error(msg)

        # ── Bước 2: Hiển thị danh sách scan & cho chọn ──
        if "nessus_scans" in st.session_state and st.session_state.nessus_scans:
            scans = st.session_state.nessus_scans

            st.subheader(f"📋 Danh sách Scans ({len(scans)} scans)")

            # Tạo DataFrame hiển thị
            scans_df = pd.DataFrame(scans)
            display_scan_cols = [c for c in ["id", "name", "status", "total_hosts", "last_modification_date"]
                                 if c in scans_df.columns]
            st.dataframe(scans_df[display_scan_cols], use_container_width=True, hide_index=True)

            # Dropdown chọn scan
            scan_options = {
                s["id"]: f"#{s['id']} — {s['name']} ({s['status']}) — {s.get('last_modification_date', '')}"
                for s in scans
            }

            selected_scan_id = st.selectbox(
                "🎯 Chọn Scan để nạp dữ liệu",
                options=list(scan_options.keys()),
                format_func=lambda x: scan_options[x],
            )

            # Tùy chọn
            col_opt1, col_opt2 = st.columns(2)
            with col_opt1:
                include_info = st.checkbox(
                    "Bao gồm lỗ hổng Info (severity=0)",
                    value=False,
                    help="Lỗ hổng Info thường rất nhiều nhưng ít giá trị. Bỏ chọn để giảm thời gian nạp.",
                )
            with col_opt2:
                auto_save = st.checkbox(
                    "Tự động lưu vào Database",
                    value=st.session_state.db_connected,
                    disabled=not st.session_state.db_connected,
                )

            # ── Bước 3: Nạp kết quả quét hoặc Kích hoạt Quét Kiểm Chứng (Closed-Loop) ──
            col_btn_fetch, col_btn_rescan = st.columns(2)
            with col_btn_rescan:
                if st.button("🚀 Kích hoạt Quét Kiểm Chứng (Launch Re-scan)", use_container_width=True):
                    client = st.session_state.nessus_client
                    with st.spinner(f"Đang gửi lệnh kích hoạt Scan #{selected_scan_id} tới Nessus Engine..."):
                        ok_launch, msg_launch = client.launch_scan(selected_scan_id)
                        if ok_launch:
                            st.success(msg_launch)
                        else:
                            st.error(msg_launch)

            with col_btn_fetch:
                fetch_clicked = st.button("📥 Nạp toàn bộ kết quả quét", type="primary", use_container_width=True)

            if fetch_clicked:
                client = st.session_state.nessus_client

                # Progress bar
                progress_bar = st.progress(0, text="Đang bắt đầu...")
                status_text = st.empty()

                def update_progress(current, total, message):
                    progress_bar.progress(current / total, text=message)
                    status_text.text(message)

                with st.spinner(""):
                    try:
                        result = client.fetch_scan_results(
                            scan_id=selected_scan_id,
                            include_info=include_info,
                            progress_callback=update_progress,
                        )

                        progress_bar.progress(1.0, text="✅ Hoàn tất!")
                        status_text.empty()

                        df_vulns = ensure_vuln_df(result.get("vulnerabilities"))
                        result["vulnerabilities"] = df_vulns
                        st.session_state.parsed_data = result
                        meta = result.get("metadata", {})

                        st.success(
                            f"✅ Đã nạp thành công **{meta.get('total_vulns', 0)} lỗ hổng** "
                            f"từ **{meta.get('total_hosts', 0)} host** (Scan: {meta.get('scan_name', '')})"
                        )

                        # Hiển thị metadata
                        st.subheader("📋 Thông tin quét")
                        mc1, mc2, mc3, mc4 = st.columns(4)
                        mc1.metric("🏷️ Tên quét", str(meta.get("scan_name", ""))[:40])
                        mc2.metric("🖥️ Số host", meta.get("total_hosts", 0))
                        mc3.metric("🐛 Tổng lỗ hổng", meta.get("total_vulns", 0))
                        mc4.metric("📡 Nguồn", "Nessus API")

                        if not df_vulns.empty:
                            # Thống kê severity
                            st.subheader("📊 Phân bổ mức nghiêm trọng")
                            sev_counts = df_vulns["severity_label"].value_counts()

                            cols = st.columns(5)
                            for i, sev in enumerate(["Critical", "High", "Medium", "Low", "Info"]):
                                count = sev_counts.get(sev, 0)
                                cols[i].metric(sev, count)

                            # Biểu đồ
                            fig = px.pie(
                                names=sev_counts.index,
                                values=sev_counts.values,
                                color=sev_counts.index,
                                color_discrete_map=SEVERITY_COLORS,
                                title="Phân bổ lỗ hổng theo mức nghiêm trọng",
                            )
                            st.plotly_chart(fig, use_container_width=True)

                            # Bảng dữ liệu
                            st.subheader("📝 Danh sách lỗ hổng")
                            display_cols = [
                                c for c in ["host_ip", "port", "plugin_id", "plugin_name",
                                             "severity_label", "cvss3_base_score", "cve_list",
                                             "exploit_available"]
                                if c in df_vulns.columns
                            ]
                            sorted_vulns = df_vulns.sort_values("severity", ascending=False)
                            st.dataframe(
                                sorted_vulns[display_cols] if display_cols else sorted_vulns,
                                use_container_width=True,
                                hide_index=True,
                                height=400,
                            )

                            # Tự động lưu hoặc nút lưu
                            st.divider()

                            if auto_save and st.session_state.db_connected:
                                try:
                                    from database.crud import insert_scan_session, insert_vulnerabilities_bulk

                                    session_id = insert_scan_session(
                                        scan_name=meta["scan_name"],
                                        source_file=meta["source_file"],
                                        file_type=meta["file_type"],
                                        scan_date=meta.get("scan_date"),
                                        scanner_name=meta.get("scanner_name"),
                                        policy_name=meta.get("policy_name"),
                                        total_hosts=meta["total_hosts"],
                                        total_vulns=meta["total_vulns"],
                                        notes=f"Imported via Nessus API ({nessus_url})",
                                    )
                                    inserted = insert_vulnerabilities_bulk(session_id, df_vulns)
                                    st.session_state.current_session_id = session_id

                                    st.success(
                                        f"💾 Đã tự động lưu phiên quét #{session_id} "
                                        f"với {inserted} lỗ hổng vào database!"
                                    )
                                except Exception as e:
                                    st.error(f"❌ Lỗi khi lưu vào DB: {e}")

                            elif st.session_state.db_connected:
                                scan_name_api = st.text_input(
                                    "Tên phiên quét (để lưu vào DB)",
                                    value=meta["scan_name"],
                                    key="api_scan_name",
                                )
                                notes_api = st.text_area(
                                    "Ghi chú (tùy chọn)",
                                    height=80,
                                    key="api_notes",
                                )

                                if st.button("💾 Lưu vào Database", key="api_save_db", use_container_width=True):
                                    with st.spinner("Đang lưu..."):
                                        try:
                                            from database.crud import insert_scan_session, insert_vulnerabilities_bulk

                                            session_id = insert_scan_session(
                                                scan_name=scan_name_api,
                                                source_file=meta["source_file"],
                                                file_type=meta["file_type"],
                                                scan_date=meta.get("scan_date"),
                                                scanner_name=meta.get("scanner_name"),
                                                policy_name=meta.get("policy_name"),
                                                total_hosts=meta["total_hosts"],
                                                total_vulns=meta["total_vulns"],
                                                notes=notes_api or f"Imported via Nessus API ({nessus_url})",
                                            )
                                            inserted = insert_vulnerabilities_bulk(session_id, df_vulns)
                                            st.session_state.current_session_id = session_id

                                            st.success(
                                                f"✅ Đã lưu phiên quét #{session_id} với {inserted} lỗ hổng!"
                                            )
                                        except Exception as e:
                                            st.error(f"❌ Lỗi khi lưu vào DB: {e}")
                            else:
                                st.warning("⚠️ Chưa kết nối database. Dữ liệu chỉ hiển thị tạm, chưa lưu.")
                        else:
                            st.warning("⚠️ Scan này không có lỗ hổng nào (hoặc chỉ có Info đã bị lọc).")

                    except Exception as e:
                        progress_bar.empty()
                        status_text.empty()
                        st.error(f"❌ Lỗi khi nạp dữ liệu từ Nessus API:\n{type(e).__name__}: {e}")

        elif "nessus_scans" not in st.session_state:
            st.info(
                "💡 **Hướng dẫn nhanh:**\n"
                "1. Nhập thông tin xác thực Nessus ở trên.\n"
                "2. Nhấn **Kết nối Nessus & Lấy danh sách Scans**.\n"
                "3. Chọn Scan và nhấn **Nạp toàn bộ kết quả quét** (hoặc **Kích hoạt Quét Kiểm Chứng**).\n\n"
                "📌 **Lấy API Keys:** Nessus → ⚙️ Settings → My Account → API Keys → Generate"
            )


# ═══════════════════════════════════════════════════════════
#  PAGE: PHÂN TÍCH AI & AUTO-REMEDIATION
# ═══════════════════════════════════════════════════════════

elif menu == "🔍 Phân tích AI":
    st.header("🔍 Trung tâm Trí tuệ Nhân tạo: Phân tích Lỗ hổng, Auto-Remediation & Security Copilot")

    if not st.session_state.ai_connected:
        st.warning(
            "⚠️ Chưa kết nối AI API. Hãy kiểm tra API key trong `.env` "
            "và nhấn **Kiểm tra kết nối** ở sidebar."
        )

    # Chọn nguồn dữ liệu
    source = st.radio(
        "Nguồn dữ liệu lỗ hổng",
        ["🗄️ Từ database (chọn phiên quét)", "📁 Từ file đã import (session hiện tại)"],
        horizontal=True,
    )

    df_vulns = pd.DataFrame()
    current_scan_label = "Session tạm"

    if source.startswith("📁"):
        if st.session_state.parsed_data and not st.session_state.parsed_data["vulnerabilities"].empty:
            df_vulns = st.session_state.parsed_data["vulnerabilities"]
            current_scan_label = st.session_state.parsed_data.get("metadata", {}).get("scan_name", "File Import")
            st.info(f"📋 Đã tải {len(df_vulns)} bản ghi từ file import gần nhất ({current_scan_label}).")
        else:
            st.info("💡 Hãy import file Nessus ở tab **Import Báo cáo** hoặc chọn nguồn **Từ database**.")
    else:
        if st.session_state.db_connected:
            try:
                from database.crud import get_all_scan_sessions, get_vulnerabilities_by_session

                sessions = get_all_scan_sessions()
                if not sessions.empty:
                    selected = st.selectbox(
                        "Chọn phiên quét",
                        sessions["id"].tolist(),
                        format_func=lambda x: f"#{x} - {sessions[sessions['id']==x]['scan_name'].values[0]}",
                    )
                    if selected:
                        df_vulns = get_vulnerabilities_by_session(selected)
                        st.session_state.current_session_id = selected
                        current_scan_label = sessions[sessions["id"] == selected]["scan_name"].values[0]
                        st.info(f"📋 Đã tải {len(df_vulns)} bản ghi từ phiên quét #{selected} ({current_scan_label}).")
                else:
                    st.info("💡 Chưa có phiên quét nào trong database. Hãy vào mục **📤 Import Báo cáo** để nạp dữ liệu từ Nessus.")
            except Exception as e:
                st.error(f"Lỗi truy vấn DB: {e}")
        else:
            st.warning("⚠️ Chưa kết nối database.")

    df_vulns = ensure_vuln_df(df_vulns)
    if not df_vulns.empty:
        st.divider()

        ai_tab_detail, ai_tab_ps1, ai_tab_copilot = st.tabs([
            "🔎 1. Phân tích Lỗ hổng & Báo cáo Quản trị",
            "⚡ 2. Auto-Remediation (Sinh Script PowerShell .ps1)",
            "💬 3. AI Security Copilot (Hỏi đáp Bảo mật)",
        ])

        # ─────────────────────────────────────────────────────────
        #  SUB-TAB 1: PHÂN TÍCH CHI TIẾT & BÁO CÁO TÓM TẮT QUẢN TRỊ
        # ─────────────────────────────────────────────────────────
        with ai_tab_detail:
            min_severity = st.select_slider(
                "Lọc mức nghiêm trọng tối thiểu",
                options=["Info", "Low", "Medium", "High", "Critical"],
                value="Medium" if not df_vulns[df_vulns["severity"] >= 2].empty else "Info",
            )
            sev_filter = {"Info": 0, "Low": 1, "Medium": 2, "High": 3, "Critical": 4}
            filtered = df_vulns[df_vulns["severity"] >= sev_filter[min_severity]].copy()

            st.write(f"📊 **{len(filtered)} lỗ hổng** từ mức `{min_severity}` trở lên")

            if not filtered.empty:
                vuln_options = filtered.apply(
                    lambda r: f"[{r.get('severity_label','?')}] {r.get('plugin_name','N/A')[:80]} — {r.get('host_ip','?')}:{r.get('port','')}",
                    axis=1,
                ).tolist()

                selected_vuln_idx = st.selectbox(
                    "Chọn lỗ hổng để phân tích chuyên sâu",
                    range(len(vuln_options)),
                    format_func=lambda i: vuln_options[i],
                )

                if selected_vuln_idx is not None:
                    vuln_row = filtered.iloc[selected_vuln_idx]
                    vuln_dict = vuln_row.to_dict()

                    with st.expander("📋 Thông tin chi tiết lỗ hổng từ Nessus", expanded=True):
                        ic1, ic2, ic3, ic4 = st.columns(4)
                        ic1.metric("Plugin ID", vuln_dict.get("plugin_id", ""))
                        ic2.metric("Severity", vuln_dict.get("severity_label", ""))
                        ic3.metric("CVSS v3", vuln_dict.get("cvss3_base_score", "N/A"))
                        ic4.metric("CVE", (vuln_dict.get("cve_list", "") or "N/A")[:30])

                        st.markdown(f"**Synopsis:** {vuln_dict.get('synopsis', 'N/A')}")
                        st.markdown(f"**Solution (Nessus):** {vuln_dict.get('solution', 'N/A')}")
                        if vuln_dict.get("plugin_output"):
                            st.code(str(vuln_dict.get("plugin_output"))[:1000], language="text")

                    col_analyze, col_batch = st.columns(2)

                    with col_analyze:
                        if st.button("🤖 Phân tích Lỗ hổng này bằng AI", type="primary", use_container_width=True):
                            if not st.session_state.ai_connected:
                                st.error("❌ Chưa kết nối AI API. Kiểm tra lại cấu hình.")
                            else:
                                with st.spinner("🧠 AI đang phân tích chuyên sâu và sinh lệnh PowerShell..."):
                                    try:
                                        from ai_engine.analyzer import analyze_vulnerability
                                        analysis = analyze_vulnerability(vuln_dict)
                                        st.session_state.last_analysis = analysis

                                        if st.session_state.db_connected and vuln_dict.get("id"):
                                            try:
                                                from database.crud import insert_ai_analysis
                                                insert_ai_analysis(
                                                    vulnerability_id=int(vuln_dict["id"]),
                                                    ai_provider=Settings.AI_PROVIDER,
                                                    model_name=Settings.get_model_name(),
                                                    **{k: v for k, v in analysis.items() if k in [
                                                        "root_cause", "risk_explanation",
                                                        "remediation_steps", "verification_cmds",
                                                        "priority_score", "additional_notes"
                                                    ]},
                                                )
                                            except Exception:
                                                pass
                                    except Exception as e:
                                        st.error(f"❌ Lỗi khi phân tích: {e}")

                    with col_batch:
                        if st.button("📑 AI Tóm tắt Báo cáo Quản trị (Toàn phiên quét)", use_container_width=True):
                            if not st.session_state.ai_connected:
                                st.error("❌ Chưa kết nối AI API.")
                            else:
                                with st.spinner("📑 AI đang tổng hợp Báo cáo Quản trị bằng Tiếng Việt..."):
                                    try:
                                        from ai_engine.analyzer import generate_scan_summary
                                        stats = {
                                            "total": len(df_vulns),
                                            "critical": int((df_vulns["severity"] == 4).sum()),
                                            "high": int((df_vulns["severity"] == 3).sum()),
                                            "medium": int((df_vulns["severity"] == 2).sum()),
                                            "low": int((df_vulns["severity"] == 1).sum()),
                                            "info": int((df_vulns["severity"] == 0).sum()),
                                        }
                                        top_df = df_vulns[df_vulns["severity"] > 0].sort_values("severity", ascending=False).head(10)
                                        top_lines = [
                                            f"- [{r.get('severity_label')}] {r.get('plugin_name')} (Host {r.get('host_ip')}:{r.get('port')}, CVSSv3: {r.get('cvss3_base_score')}, CVE: {r.get('cve_list')})"
                                            for _, r in top_df.iterrows()
                                        ]
                                        summary_md = generate_scan_summary(stats, "\n".join(top_lines) or "Không có lỗ hổng nghiêm trọng.")
                                        st.session_state.last_scan_summary = summary_md
                                    except Exception as e:
                                        st.error(f"❌ Lỗi khi tạo tóm tắt: {e}")

                    if "last_scan_summary" in st.session_state and st.session_state.last_scan_summary:
                        with st.expander("📑 BÁO CÁO TÓM TẮT QUẢN TRỊ AN NINH (AI EXECUTIVE SUMMARY)", expanded=True):
                            st.markdown(st.session_state.last_scan_summary)
                            st.download_button(
                                "📥 Tải Báo cáo Quản trị (.md)",
                                st.session_state.last_scan_summary,
                                file_name="AI_Executive_Security_Summary.md",
                                mime="text/markdown",
                            )

                    if "last_analysis" in st.session_state and st.session_state.last_analysis:
                        analysis = st.session_state.last_analysis

                        st.divider()
                        st.subheader("🧠 Kết quả phân tích chuyên sâu từ AI")

                        ps = analysis.get("priority_score", 5)
                        ps_color = "🔴" if ps >= 8 else "🟠" if ps >= 5 else "🟢"
                        st.markdown(f"### {ps_color} Điểm ưu tiên xử lý: {ps}/10")

                        tab1, tab2, tab3, tab_ps, tab4, tab5 = st.tabs([
                            "🔎 Nguyên nhân",
                            "⚠️ Rủi ro (CIA)",
                            "🔧 Khắc phục",
                            "⚡ PowerShell Script",
                            "✅ Xác minh",
                            "📝 Ghi chú",
                        ])

                        with tab1:
                            st.markdown("### 🔎 Nguyên nhân gốc rễ")
                            st.markdown(analysis.get("root_cause", "Chưa có phân tích."))

                        with tab2:
                            st.markdown("### ⚠️ Diễn giải rủi ro & Kịch bản khai thác")
                            st.markdown(analysis.get("risk_explanation", "Chưa có phân tích."))

                        with tab3:
                            st.markdown("### 🔧 Các bước khắc phục chi tiết")
                            st.markdown(analysis.get("remediation_steps", "Chưa có phân tích."))

                        with tab_ps:
                            st.markdown("### ⚡ Đoạn mã PowerShell khắc phục tự động")
                            ps_code = analysis.get("powershell_script") or analysis.get("verification_cmds", "# Chưa có script")
                            st.code(ps_code, language="powershell")
                            st.download_button(
                                "📥 Tải Script vá lỗ hổng này (.ps1)",
                                ps_code,
                                file_name=f"Fix_Plugin_{vuln_dict.get('plugin_id', 'vuln')}.ps1",
                                mime="text/plain",
                            )

                        with tab4:
                            st.markdown("### ✅ Lệnh xác minh sau khi vá")
                            st.code(analysis.get("verification_cmds", "# Chưa có lệnh xác minh"), language="powershell")

                        with tab5:
                            st.markdown("### 📝 Lưu ý bổ sung")
                            st.markdown(analysis.get("additional_notes", "Không có ghi chú thêm."))

        # ─────────────────────────────────────────────────────────
        #  SUB-TAB 2: AUTO-REMEDIATION (SINH SCRIPT POWERSHELL TỔNG HỢP)
        # ─────────────────────────────────────────────────────────
        with ai_tab_ps1:
            st.subheader("⚡ Tự động hóa Khắc phục Lỗ hổng bằng PowerShell (Auto-Remediation Engine)")
            st.markdown("""
            Module **Auto-Remediation** tự động tổng hợp các lỗ hổng phát hiện trên máy mục tiêu **Windows 11 (`192.168.104.129`)** và sinh kịch bản **PowerShell (`.ps1`)** chuẩn xác để quản trị viên kiểm tra và áp dụng ngay lập tức:
            - **Critical (CVSS 9.8 - VLC 2.2.0)**: Tự động chạy uninstaller silent và dọn sạch thư mục `C:\\Program Files\\VideoLAN\\VLC`.
            - **High (CVSS 8.8 - WinVerifyTrust CVE-2013-3900)**: Tự động tạo khóa Registry `EnableCertPaddingCheck = 1` cho cả nhánh 64-bit và 32-bit (`Wow6432Node`).
            - **Medium (ICMP Timestamp CVE-1999-0524)**: Tạo rule `Windows Defender Firewall` chặn chính xác gói tin `ICMPv4 Type 13 & 14`.
            - **Medium (SMB Signing)**: Bật chính sách bắt buộc ký số SMB (`RequireSecuritySignature = 1`).
            """)

            from ai_engine.analyzer import build_standard_lab_remediation_ps1, generate_powershell_remediation_script

            col_ps_mode1, col_ps_mode2 = st.columns(2)
            with col_ps_mode1:
                if st.button("⚡ Sinh Script PowerShell Chuẩn Thực Nghiệm Lab (.ps1)", type="primary", use_container_width=True):
                    st.session_state.generated_ps1 = build_standard_lab_remediation_ps1("192.168.104.129")
            with col_ps_mode2:
                if st.button("🤖 Nhờ AI Tùy biến Script theo Danh sách Lỗ hổng Hiện tại", use_container_width=True):
                    with st.spinner("🤖 AI đang biên dịch kịch bản PowerShell tổng hợp..."):
                        vulns_for_ps = df_vulns[df_vulns["severity"] > 0].to_dict(orient="records")
                        st.session_state.generated_ps1 = generate_powershell_remediation_script(
                            vulns_for_ps, target_ip="192.168.104.129", use_ai=True
                        )

            ps1_content = st.session_state.get("generated_ps1") or build_standard_lab_remediation_ps1("192.168.104.129")
            st.code(ps1_content, language="powershell")

            st.download_button(
                "📥 Tải Kịch bản Auto_Remediation_Win11.ps1",
                ps1_content,
                file_name="Auto_Remediation_Win11_192.168.104.129.ps1",
                mime="text/plain",
                type="primary",
                use_container_width=True,
            )

        # ─────────────────────────────────────────────────────────
        #  SUB-TAB 3: AI SECURITY COPILOT (CHATBOT TƯƠNG TÁC)
        # ─────────────────────────────────────────────────────────
        with ai_tab_copilot:
            st.subheader("💬 AI Security Copilot — Trợ lý Hỏi đáp An toàn Thông tin")
            st.caption("Hỏi đáp trực tiếp bằng Tiếng Việt về kết quả quét, kịch bản tấn công RCE, SMB/Registry hoặc câu hỏi phản biện đồ án.")

            # Gợi ý câu hỏi nhanh
            q_col1, q_col2, q_col3 = st.columns(3)
            quick_q = None
            if q_col1.button("❓ Tại sao White-Box thấy 47 mục còn Black-Box chỉ thấy 2?", use_container_width=True):
                quick_q = "Giải thích tại sao quét White-Box có xác thực SMB/Registry lại phát hiện được 47 mục (có VLC 9.8 và WinVerifyTrust 8.8) trong khi quét Black-Box chỉ thấy 2 lỗi Medium?"
            if q_col2.button("❓ Giải thích cơ chế lỗi WinVerifyTrust CVE-2013-3900?", use_container_width=True):
                quick_q = "Giải thích chi tiết cơ chế lỗ hổng WinVerifyTrust CVE-2013-3900 (CVSS 8.8) và tại sao phải cấu hình EnableCertPaddingCheck ở cả nhánh 32-bit và 64-bit?"
            if q_col3.button("❓ Thứ tự ưu tiên vá lỗi trên máy 192.168.104.129?", use_container_width=True):
                quick_q = "Dựa trên kết quả quét hiện tại của máy 192.168.104.129, hãy xếp thứ tự ưu tiên khắc phục và giải thích lý do theo CVSS v3 và VPR."

            for msg in st.session_state.copilot_messages:
                with st.chat_message(msg["role"]):
                    st.markdown(msg["content"])

            user_question = st.chat_input("Nhập câu hỏi bảo mật cho AI Security Copilot...") or quick_q
            if user_question:
                st.session_state.copilot_messages.append({"role": "user", "content": user_question})
                with st.chat_message("user"):
                    st.markdown(user_question)

                with st.chat_message("assistant"):
                    with st.spinner("🤖 AI Security Copilot đang suy nghĩ..."):
                        try:
                            from ai_engine.analyzer import ask_security_copilot
                            non_info = df_vulns[df_vulns["severity"] > 0]
                            ctx_lines = [
                                f"Phiên quét: {current_scan_label} | Tổng bản ghi: {len(df_vulns)} | Lỗ hổng (Severity>0): {len(non_info)}"
                            ]
                            for _, r in non_info.head(15).iterrows():
                                ctx_lines.append(
                                    f"- [{r.get('severity_label')}] Plugin {r.get('plugin_id')}: {r.get('plugin_name')} "
                                    f"(Host {r.get('host_ip')}:{r.get('port')}, CVSSv3={r.get('cvss3_base_score')}, CVE={r.get('cve_list')})"
                                )
                            answer = ask_security_copilot(
                                user_question,
                                "\n".join(ctx_lines),
                                st.session_state.copilot_messages[:-1],
                            )
                            st.markdown(answer)
                            st.session_state.copilot_messages.append({"role": "assistant", "content": answer})
                        except Exception as e:
                            st.error(f"❌ Lỗi gọi AI Copilot: {e}")


# ═══════════════════════════════════════════════════════════
#  PAGE: CÔNG CỤ NMAP (NETWORK SCANNER & ATTACK/DEFENSE VERIFIER)
# ═══════════════════════════════════════════════════════════

elif menu == "🛰️ Công cụ Nmap":
    from utils.nmap_verifier import (
        SCAN_PROFILES,
        TIMING_TEMPLATES,
        detect_nmap_environment,
        list_nse_scripts,
        validate_targets,
        sanitize_extra_args,
        build_nmap_command,
        display_command,
        run_nmap_streaming,
        parse_nmap_xml,
        evaluate_nmap_security_findings,
        evaluate_nping_security_findings,
        compare_security_verdicts,
        run_nping,
        nping_icmp_args,
        nping_tcp_args,
        nping_udp_args,
    )

    st.header("🛰️ Công cụ Nmap — Rà quét Mạng & Chứng minh Tấn công / Phòng thủ")
    nmap_info = detect_nmap_environment()

    if nmap_info["available"]:
        st.caption(f"{nmap_info['version']} · `{nmap_info['nmap_path']}`")
    else:
        st.error("Không tìm thấy `nmap.exe`. Cài Nmap (kèm Npcap) rồi khởi động lại Web.")
        st.stop()

    if "nmap_history" not in st.session_state or st.session_state.nmap_history is None:
        st.session_state.nmap_history = []

    def _render_finding_cards(findings_list: list[dict]):
        """Hiển thị danh sách thẻ đánh giá an ninh (FAIL / WARN / PASS) kèm kịch bản tấn công & lệnh phòng thủ."""
        for f in findings_list:
            v = f.get("verdict", "WARN")
            if v == "FAIL":
                bg, border, head_c = "#fef2f2", "#dc2626", "#991b1b"
            elif v == "PASS":
                bg, border, head_c = "#f0fdf4", "#16a34a", "#166534"
            else:
                bg, border, head_c = "#fffbeb", "#d97706", "#92400e"

            st.markdown(
                f"""
                <div style="background-color:{bg};border:2px solid {border};border-radius:10px;padding:16px 20px;margin-bottom:12px;">
                    <div style="display:flex;justify-content:space-between;align-items:center;flex-wrap:wrap;gap:8px;">
                        <h4 style="margin:0;color:{head_c};font-size:1.08rem;">🎯 {f['title']}</h4>
                        <span style="background-color:{border};color:#ffffff;padding:4px 12px;border-radius:18px;font-weight:700;font-size:0.84rem;">
                            {f['badge']}
                        </span>
                    </div>
                    <p style="margin:10px 0 6px 0;color:#0f172a;font-size:0.95rem;">
                        <b>📌 Bằng chứng thu được (Evidence):</b> <code>{f['evidence']}</code>
                    </p>
                    <p style="margin:6px 0;color:#0f172a;font-size:0.95rem;">
                        <b>⚔️ Phân tích Kịch bản Tấn công / Phòng thủ:</b> {f['attack_scenario']}
                    </p>
                    <p style="margin:6px 0 0 0;color:#0f172a;font-size:0.95rem;">
                        <b>🛡️ Khuyến nghị xử lý:</b> {f['recommendation']}
                    </p>
                </div>
                """,
                unsafe_allow_html=True,
            )
            if f.get("remediation_cmd"):
                with st.expander(f"⌨️ Lệnh PowerShell / Firewall Phòng thủ cho: {f['title']}", expanded=(v == "FAIL")):
                    st.code(f["remediation_cmd"], language="powershell")

    with st.expander("📖 Hướng dẫn sử dụng & Quy trình Chứng minh Tấn công / Phòng thủ", expanded=False):
        st.markdown("""
**1. Cách thực hiện Kịch bản Tấn công Thăm dò → Phòng thủ → Kiểm chứng (Closed-Loop)**
- **Bước 1 (Tấn công thăm dò - Trước khi vá)**:
  - Tại tab **🔎 Nmap Scan**, nhập IP mục tiêu và chọn hồ sơ **`Kiểm định An ninh SMB & Ký số (Port 445)`** hoặc **`Kiểm định Bề mặt Tấn công Dịch vụ Windows`**, tích chọn `-Pn` nếu cần rồi bấm **▶️ Chạy Nmap**.
  - Hệ thống sẽ tự động phân tích output thực tế, chỉ ra bằng chứng lỗ hổng (**`FAIL ❌`** / **`WARN ⚠️`**), giải thích **Kịch bản Tấn công (Red Team)** và cung cấp **Lệnh PowerShell Phòng thủ (Blue Team)**.
  - Tại tab **📡 Nping**, chọn giao thức **ICMP → Loại `13 – Timestamp Request`** và bấm **📡 Gửi gói tin** để kiểm tra xem mục tiêu có bị lộ thời gian hệ thống (`CVE-1999-0524`) hay không.
- **Bước 2 (Thực thi Phòng thủ)**:
  - Copy câu lệnh PowerShell phòng thủ được khuyến nghị ngay dưới thẻ kết quả (hoặc bấm nút **🤖 Phân tích Chuyên sâu bằng AI**) và chạy trên máy mục tiêu với quyền Administrator.
- **Bước 3 (Kiểm chứng Sau Phòng thủ & Đối chiếu)**:
  - Bấm chạy lại đúng lệnh Nmap / Nping vừa rồi. Thẻ đánh giá sẽ lập tức chuyển từ **`FAIL ❌`** sang **`PASS ✅ (Đã phòng thủ an toàn)`**.
  - Sang tab **🕘 Lịch sử & Chứng minh Trước / Sau** để xem bảng đối chiếu chuyển đổi trạng thái **`FAIL ❌ → PASS ✅`** giữa 2 lần quét.
        """)

    tab_scan, tab_nping, tab_hist = st.tabs([
        "🔎 Nmap Scan & Phân tích An ninh",
        "📡 Nping (Kiểm thử Gói tin & Tường lửa)",
        "🕘 Lịch sử & Chứng minh Trước / Sau Phòng thủ",
    ])

    # ─────────────────────────────────────────────
    #  TAB 1: NMAP SCAN
    # ─────────────────────────────────────────────
    with tab_scan:
        c1, c2 = st.columns([3, 2])
        with c1:
            target_text = st.text_input("Mục tiêu (IP / Dải mạng / Hostname)", value="", placeholder="Nhập địa chỉ IP hoặc dải mạng cần kiểm tra...")
        with c2:
            profile_names = list(SCAN_PROFILES.keys())
            profile = st.selectbox(
                "Hồ sơ quét & Kiểm định",
                profile_names,
                index=0,
                format_func=lambda n: ("🔒 " if SCAN_PROFILES[n]["admin"] else "") + n,
            )
        st.caption(f"💡 **Mô tả hồ sơ:** {SCAN_PROFILES[profile]['desc']}")

        c3, c4, c5 = st.columns([2, 2, 1])
        with c3:
            ports = st.text_input(
                "Cổng (Port)",
                value="",
                placeholder="VD: 22,80,443,445 hoặc 1-1024",
                disabled=not SCAN_PROFILES[profile]["uses_ports"],
            )
        with c4:
            timing_label = st.selectbox("Tốc độ (-T)", list(TIMING_TEMPLATES.keys()), index=4)
        with c5:
            st.write("")
            skip_ping = st.checkbox("-Pn", value=True, help="Bỏ qua bước ping, quét thẳng vào mục tiêu (rất hữu ích khi tường lửa Windows chặn Ping ICMP).")

        with st.expander("⚙️ Tùy chọn nâng cao (Chọn thêm NSE script, tham số bổ sung)"):
            all_scripts = list_nse_scripts(nmap_info["scripts_dir"])
            sel_scripts = st.multiselect(
                f"NSE script ({len(all_scripts)} script có sẵn trong bản cài)",
                all_scripts,
                placeholder="Gõ để tìm, VD: smb2-security-mode, smb-protocols, ssl-enum-ciphers, vuln...",
            )
            script_args = st.text_input("--script-args", value="", placeholder="VD: smbusername=admin,smbpassword=...")
            extra_text = st.text_input("Tham số bổ sung", value="", placeholder="VD: --top-ports 200 --open")
            timeout_s = st.number_input("Thời gian chờ tối đa (giây)", min_value=10, max_value=3600, value=600, step=10)

        targets, t_err = validate_targets(target_text) if target_text.strip() else ([], "")
        extra_args, e_err = sanitize_extra_args(extra_text)
        if profile == "Chỉ chạy NSE script tự chọn" and not sel_scripts:
            st.info("Hồ sơ này cần chọn ít nhất một NSE script trong mục *Tùy chọn nâng cao*.")

        cmd = None
        if targets and not e_err:
            cmd = build_nmap_command(
                nmap_info["nmap_path"], targets, profile,
                ports=ports if SCAN_PROFILES[profile]["uses_ports"] else "",
                timing=TIMING_TEMPLATES[timing_label],
                skip_ping=skip_ping,
                scripts=sel_scripts,
                script_args=script_args,
                extra_args=extra_args,
            )
            st.code(display_command(cmd), language="bash")
        if t_err:
            st.error(t_err)
        if e_err:
            st.error(e_err)

        can_run = cmd is not None and not (profile == "Chỉ chạy NSE script tự chọn" and not sel_scripts)
        if st.button("▶️ Chạy Nmap & Phân tích An ninh", type="primary", disabled=not can_run):
            live_box = st.empty()
            with st.spinner("Nmap đang quét và thu thập bằng chứng từ mục tiêu..."):
                run = run_nmap_streaming(
                    cmd, timeout=int(timeout_s),
                    on_line=lambda txt: live_box.code(txt[-6000:], language="text"),
                )
            live_box.empty()
            parsed = parse_nmap_xml(run["xml"])
            findings = evaluate_nmap_security_findings(parsed, run["raw_output"])
            st.session_state.nmap_history.insert(0, {
                "id": len(st.session_state.nmap_history) + 1,
                "command": display_command(cmd),
                "targets": " ".join(targets),
                "profile": profile,
                **run,
                "parsed": parsed,
                "findings": findings,
                "ai_report": None,
            })

        # ── Hiển thị kết quả lần chạy gần nhất ──
        if st.session_state.nmap_history:
            run = st.session_state.nmap_history[0]
            parsed = run["parsed"]
            findings = run.get("findings") or evaluate_nmap_security_findings(parsed, run["raw_output"])
            run["findings"] = findings

            st.divider()
            st.subheader(f"📊 Kết quả Kiểm định Lần chạy #{run['id']}")
            st.caption(f"`{run['command']}` · bắt đầu {run['started']} · {run['duration_s']} giây · mã thoát {run['returncode']}")

            if parsed["error"]:
                st.warning(parsed["error"])

            stats = parsed.get("stats") or {}
            hosts = parsed["hosts"]
            all_ports = [p for h in hosts for p in h["ports"]]
            fail_cnt = sum(1 for f in findings if f["verdict"] == "FAIL")
            warn_cnt = sum(1 for f in findings if f["verdict"] == "WARN")
            pass_cnt = sum(1 for f in findings if f["verdict"] == "PASS")

            m1, m2, m3, m4, m5 = st.columns(5)
            m1.metric("🖥️ Host đang bật", stats.get("up", sum(1 for h in hosts if h["status"] == "up")))
            m2.metric("🔌 Cổng mở (Open)", sum(1 for p in all_ports if p["state"] == "open"))
            m3.metric("❌ Lỗ hổng / Điểm yếu (FAIL)", fail_cnt)
            m4.metric("⚠️ Bề mặt Phơi lộ (WARN)", warn_cnt)
            m5.metric("✅ Đã Phòng thủ (PASS)", pass_cnt)

            r_tab_sec, r_tab1, r_tab2, r_tab3 = st.tabs([
                f"🛡️ Chứng minh Lỗ hổng & Khuyến nghị Phòng thủ ({len(findings)})",
                "🖥️ Bảng Host & Cổng Dịch vụ",
                "📜 Kết quả NSE Script",
                "💻 Output Gốc (.txt / .xml)",
            ])

            with r_tab_sec:
                st.markdown("#### 🔍 Đánh giá Tự động Bề mặt Tấn công & Trạng thái Phòng thủ (Dựa trên dữ liệu quét thực tế)")
                _render_finding_cards(findings)

                st.divider()
                st.markdown("#### 🤖 Trợ lý AI Phân tích Chuyên sâu Kết quả Nmap (Red Team Attack ↔ Blue Team Defense)")
                if st.button("🤖 Phân tích Kết quả Nmap này bằng AI & Sinh Kịch bản Phòng thủ", key=f"ai_nmap_btn_{run['id']}", type="primary"):
                    if not st.session_state.ai_connected:
                        st.error("❌ Chưa kết nối AI API. Hãy kiểm tra kết nối ở thanh bên trái.")
                    else:
                        with st.spinner("🤖 AI đang phân tích log Nmap, dựng kịch bản tấn công và viết lệnh phòng thủ..."):
                            try:
                                from ai_engine.analyzer import analyze_nmap_scan_with_ai
                                run["ai_report"] = analyze_nmap_scan_with_ai(
                                    run["command"], run["raw_output"], findings
                                )
                            except Exception as e:
                                st.error(f"❌ Lỗi gọi AI: {e}")

                if run.get("ai_report"):
                    st.markdown(run["ai_report"])
                    st.download_button(
                        "📥 Tải Báo cáo Phân tích Nmap của AI (.md)",
                        run["ai_report"],
                        file_name=f"AI_Nmap_Security_Analysis_Run_{run['id']}.md",
                        mime="text/markdown",
                    )

            with r_tab1:
                if not hosts:
                    st.info("Không có host nào trong kết quả.")
                host_rows = []
                for h in hosts:
                    host_rows.append({
                        "IP": h["ip"],
                        "Hostname": h["hostnames"],
                        "Trạng thái": h["status"],
                        "Lý do": h["status_reason"],
                        "MAC": h["mac"],
                        "Nhà SX card mạng": h["vendor"],
                        "Hệ điều hành (dự đoán)": "; ".join(f"{o['name']} ({o['accuracy']}%)" for o in h["os"]),
                    })
                if host_rows:
                    st.dataframe(pd.DataFrame(host_rows), use_container_width=True, hide_index=True)

                port_rows = []
                for h in hosts:
                    for p in h["ports"]:
                        port_rows.append({
                            "IP": h["ip"],
                            "Cổng": p["port"],
                            "Giao thức": p["protocol"],
                            "Trạng thái": p["state"],
                            "Lý do": p["reason"],
                            "Dịch vụ": p["service"],
                            "Sản phẩm": p["product"],
                            "Phiên bản": p["version"],
                            "Thông tin thêm": p["extrainfo"],
                        })
                if port_rows:
                    st.dataframe(pd.DataFrame(port_rows), use_container_width=True, hide_index=True)
                elif hosts:
                    st.caption("Lần chạy này không quét cổng hoặc không có cổng nào được báo cáo.")

            with r_tab2:
                script_count = 0
                for h in hosts:
                    for p in h["ports"]:
                        for s in p["scripts"]:
                            script_count += 1
                            with st.expander(f"{h['ip']}:{p['port']}/{p['protocol']} — {s['id']}", expanded=True):
                                st.code(s["output"] or "(không có output)", language="text")
                    for s in h["host_scripts"]:
                        script_count += 1
                        with st.expander(f"{h['ip']} (host script) — {s['id']}", expanded=True):
                            st.code(s["output"] or "(không có output)", language="text")
                if script_count == 0:
                    st.caption("Không có kết quả NSE script trong lần chạy này.")

            with r_tab3:
                st.code(run["raw_output"] or "(trống)", language="text")
                d1, d2 = st.columns(2)
                d1.download_button("📥 Tải output (.txt)", run["raw_output"], file_name=f"nmap_run_{run['id']}.txt")
                if run["xml"]:
                    d2.download_button("📥 Tải XML (.xml)", run["xml"], file_name=f"nmap_run_{run['id']}.xml", mime="application/xml")

            # ── Đối chiếu với Nessus (chỉ khi DB có dữ liệu thật) ──
            if st.session_state.db_connected and hosts:
                try:
                    from database.crud import get_all_scan_sessions, get_vulnerabilities_by_session
                    sess = get_all_scan_sessions()
                    if not sess.empty:
                        with st.expander("🔗 Đối chiếu Chéo với Phiên quét Tenable Nessus trong Database", expanded=True):
                            sid = st.selectbox(
                                "Chọn phiên quét Nessus để đối chiếu",
                                sess["id"].tolist(),
                                format_func=lambda x: f"#{x} - {sess[sess['id']==x]['scan_name'].values[0]}",
                                key="nmap_cmp_session",
                            )
                            dfn = ensure_vuln_df(get_vulnerabilities_by_session(int(sid)))
                            rows = []
                            for h in hosts:
                                dfh = dfn[dfn["host_ip"] == h["ip"]]
                                nmap_ports = {p["port"]: p for p in h["ports"]}
                                nessus_ports = {int(x) for x in dfh["port"].dropna().tolist() if int(x) > 0}
                                for port in sorted(set(nmap_ports) | nessus_ports):
                                    np_ = nmap_ports.get(port)
                                    sub = dfh[(dfh["port"] == port) & (dfh["severity"] > 0)]
                                    rows.append({
                                        "IP": h["ip"],
                                        "Cổng": port,
                                        "Trạng thái trên Nmap": f"{np_['state']} ({np_['service']})" if np_ else "không quét / không thấy",
                                        "Nessus: Số lỗ hổng (Low+)": len(sub),
                                        "Nessus: Mức cao nhất": SEVERITY_MAP.get(int(sub["severity"].max()), "") if not sub.empty else "Info / An toàn",
                                        "Nessus: Tên lỗ hổng phát hiện": "; ".join(sub["plugin_name"].astype(str).head(3).tolist()) or "Chỉ ghi nhận cổng / Info",
                                    })
                            if rows:
                                st.dataframe(pd.DataFrame(rows), use_container_width=True, hide_index=True)
                            else:
                                st.caption("Không có host nào trùng giữa lần chạy Nmap và phiên Nessus đã chọn.")
                except Exception as e:
                    st.caption(f"Không đối chiếu được với Database: {e}")

    # ─────────────────────────────────────────────
    #  TAB 2: NPING (KIỂM THỬ GÓI TIN & TƯỜNG LỬA)
    # ─────────────────────────────────────────────
    with tab_nping:
        if not nmap_info["nping_path"]:
            st.warning("Không tìm thấy `nping.exe` trong thư mục cài Nmap.")
        else:
            n1, n2, n3 = st.columns([3, 1.5, 1])
            with n1:
                np_target = st.text_input("Mục tiêu (IP / Hostname)", value="", placeholder="Nhập địa chỉ IP cần bắn gói tin kiểm thử...", key="np_target")
            with n2:
                np_mode = st.selectbox("Giao thức", ["ICMP", "TCP", "UDP"])
            with n3:
                np_count = st.number_input("Số gói", min_value=1, max_value=50, value=2)

            icmp_types = {
                "13 – Timestamp Request (Kiểm định lỗ hổng CVE-1999-0524 / Plugin 10114)": 13,
                "8 – Echo Request (Kiểm tra Ping tiêu chuẩn)": 8,
                "15 – Information Request": 15,
                "17 – Address Mask Request": 17,
            }
            np_args = None
            if np_mode == "ICMP":
                itype = st.selectbox("Loại gói tin ICMP", list(icmp_types.keys()))
                if np_target.strip():
                    np_args = nping_icmp_args(np_target.strip(), icmp_types[itype], int(np_count))
            else:
                p1, p2 = st.columns(2)
                with p1:
                    np_ports = st.text_input("Cổng đích", value="", placeholder="VD: 80 hoặc 445")
                with p2:
                    np_flags = st.selectbox("Cờ TCP", ["syn", "ack", "fin", "rst", "syn,ack", "psh,ack"], disabled=np_mode != "TCP")
                if np_target.strip() and np_ports.strip():
                    np_args = (nping_tcp_args(np_target.strip(), np_ports.strip(), np_flags, int(np_count))
                               if np_mode == "TCP" else
                               nping_udp_args(np_target.strip(), np_ports.strip(), int(np_count)))

            np_valid = False
            if np_args:
                _t, _err = validate_targets(np_target)
                np_valid = bool(_t) and len(_t) == 1
                if _err:
                    st.error(_err)
                else:
                    st.code("nping " + " ".join(np_args), language="bash")

            if st.button("📡 Bắn Gói Tin Kiểm Chứng & Đánh giá Tường lửa", type="primary", disabled=not np_valid):
                with st.spinner("Đang gửi gói tin thăm dò và phân tích phản hồi..."):
                    raw_res = run_nping(nmap_info["nping_path"], np_args)
                    np_findings = evaluate_nping_security_findings(
                        np_mode, np_args, raw_res["raw_output"], raw_res["stats"]
                    )
                    st.session_state.nping_last = {
                        "cmd": "nping " + " ".join(np_args),
                        "findings": np_findings,
                        **raw_res,
                    }

            res = st.session_state.get("nping_last")
            if res:
                st.divider()
                st.caption(f"`{res['cmd']}` · {res['started']}")
                if res["stats"]:
                    s1, s2, s3, s4 = st.columns(4)
                    s1.metric("📤 Đã gửi (Sent)", res["stats"]["sent"])
                    s2.metric("📥 Nhận phản hồi (Rcvd)", res["stats"]["rcvd"])
                    s3.metric("🛡️ Đã bị chặn / Mất (Lost)", res["stats"]["lost"])
                    s4.metric("📊 Tỷ lệ chặn / mất", f"{res['stats']['loss_pct']}%")

                if res.get("findings"):
                    st.markdown("#### 🛡️ Kết luận Kiểm định Gói tin & Khuyến nghị Tường lửa")
                    _render_finding_cards(res["findings"])

                with st.expander("💻 Xem Log Gói tin Nping Chi tiết", expanded=True):
                    st.code(res["raw_output"] or "(trống)", language="text")

    # ─────────────────────────────────────────────
    #  TAB 3: LỊCH SỬ & CHỨNG MINH TRƯỚC / SAU PHÒNG THỦ
    # ─────────────────────────────────────────────
    with tab_hist:
        hist = st.session_state.nmap_history
        if not hist:
            st.caption("Chưa có lần chạy Nmap nào trong phiên làm việc này.")
        else:
            st.markdown("#### 📋 Danh sách các lần quét Nmap trong phiên")
            st.dataframe(
                pd.DataFrame([{
                    "#": r["id"],
                    "Thời điểm": r["started"],
                    "Hồ sơ": r["profile"],
                    "Mục tiêu": r["targets"],
                    "Lỗ hổng (FAIL)": sum(1 for f in (r.get("findings") or []) if f["verdict"] == "FAIL"),
                    "Cảnh báo (WARN)": sum(1 for f in (r.get("findings") or []) if f["verdict"] == "WARN"),
                    "An toàn (PASS)": sum(1 for f in (r.get("findings") or []) if f["verdict"] == "PASS"),
                    "Lệnh": r["command"],
                } for r in hist]),
                use_container_width=True, hide_index=True,
            )

            if len(hist) >= 2:
                st.divider()
                st.subheader("🏆 Đối chiếu Chứng minh Trước & Sau Khi Phòng thủ (Before vs. After Defense)")
                ids = [r["id"] for r in hist]
                h1, h2 = st.columns(2)
                a_id = h1.selectbox(
                    "Lần chạy A (Trước khi phòng thủ / Baseline)",
                    ids,
                    index=1,
                    format_func=lambda x: f"Lần #{x} ({next(r['started'] for r in hist if r['id']==x)})",
                )
                b_id = h2.selectbox(
                    "Lần chạy B (Sau khi phòng thủ / Verification)",
                    ids,
                    index=0,
                    format_func=lambda x: f"Lần #{x} ({next(r['started'] for r in hist if r['id']==x)})",
                )
                ra = next(r for r in hist if r["id"] == a_id)
                rb = next(r for r in hist if r["id"] == b_id)

                verdict_cmp = compare_security_verdicts(
                    ra.get("findings") or [], rb.get("findings") or []
                )
                if verdict_cmp:
                    st.markdown("##### 🛡️ Bảng Chứng minh Chuyển đổi Trạng thái An ninh (FAIL ❌ → PASS ✅)")
                    st.dataframe(pd.DataFrame(verdict_cmp), use_container_width=True, hide_index=True)

                def _flat(run):
                    out = {}
                    for h in run["parsed"]["hosts"]:
                        out[(h["ip"], "host", "")] = {"state": h["status"], "scripts": ""}
                        for p in h["ports"]:
                            out[(h["ip"], p["port"], p["protocol"])] = {
                                "state": p["state"],
                                "scripts": "\n".join(f"[{s['id']}] {s['output']}" for s in p["scripts"]),
                            }
                        for s in h["host_scripts"]:
                            out[(h["ip"], "hostscript", s["id"])] = {"state": "", "scripts": s["output"]}
                    return out

                fa, fb = _flat(ra), _flat(rb)
                diff_rows = []
                for key in sorted(set(fa) | set(fb), key=lambda k: (k[0], str(k[1]), k[2])):
                    va, vb = fa.get(key), fb.get(key)
                    sa = va["state"] if va else "—"
                    sb = vb["state"] if vb else "—"
                    sca = va["scripts"] if va else ""
                    scb = vb["scripts"] if vb else ""
                    changed = (sa != sb) or (sca != scb)
                    diff_rows.append({
                        "IP": key[0], "Cổng / mục": f"{key[1]}/{key[2]}" if key[2] else str(key[1]),
                        f"A (#{a_id})": sa, f"B (#{b_id})": sb,
                        "Script Output A": sca[:300], "Script Output B": scb[:300],
                        "Thay đổi": "⚠️ Có" if changed else "",
                    })
                df_diff = pd.DataFrame(diff_rows)
                with st.expander("🔍 Chi tiết Chênh lệch Cổng & Script Output giữa 2 lần chạy", expanded=True):
                    only_changed = st.checkbox("Chỉ hiện dòng có thay đổi", value=False)
                    if only_changed and not df_diff.empty:
                        df_diff = df_diff[df_diff["Thay đổi"] != ""]
                    if df_diff.empty:
                        st.caption("Không có khác biệt giữa 2 lần chạy.")
                    else:
                        st.dataframe(df_diff, use_container_width=True, hide_index=True)

            if st.button("🗑️ Xóa lịch sử Nmap"):
                st.session_state.nmap_history = []
                st.session_state.nping_last = None
                st.rerun()


# ═══════════════════════════════════════════════════════════
#  PAGE: DASHBOARD & RISK MATRIX
# ═══════════════════════════════════════════════════════════

elif menu == "📊 Dashboard":
    st.header("📊 Dashboard Phân tích Ma trận Rủi ro Lỗ hổng (Vulnerability Risk Matrix)")

    df_vulns = pd.DataFrame()

    # Ưu tiên dữ liệu từ DB, fallback sang parsed_data
    if st.session_state.db_connected:
        try:
            from database.crud import get_all_scan_sessions, get_vulnerabilities_by_session

            sessions = get_all_scan_sessions()
            if not sessions.empty:
                selected = st.selectbox(
                    "Chọn phiên quét",
                    sessions["id"].tolist(),
                    format_func=lambda x: f"#{x} - {sessions[sessions['id']==x]['scan_name'].values[0]}",
                    key="dash_session",
                )
                df_vulns = get_vulnerabilities_by_session(selected)
        except Exception:
            pass

    if df_vulns.empty and st.session_state.parsed_data:
        df_vulns = st.session_state.parsed_data.get("vulnerabilities", pd.DataFrame())

    df_vulns = ensure_vuln_df(df_vulns)

    if df_vulns.empty:
        st.info("💡 Chưa có dữ liệu lỗ hổng. Hãy vào mục **📤 Import Báo cáo** để nạp file Nessus hoặc kết nối Nessus API trước khi xem Dashboard.")
    else:
        # ── Bộ lọc đa chiều (Search CVE, Host, Port, Severity) ──
        with st.expander("🔍 Bộ lọc & Tìm kiếm Đa chiều (CVE, Cổng dịch vụ, Máy chủ, Mức độ)", expanded=True):
            f_col1, f_col2, f_col3, f_col4 = st.columns(4)
            with f_col1:
                search_kw = st.text_input("🔎 Tìm theo CVE / Tên Plugin", placeholder="VD: CVE-2013-3900, VLC, SMB...")
            with f_col2:
                hosts_list = ["Tất cả"] + sorted(df_vulns["host_ip"].dropna().unique().tolist())
                sel_host = st.selectbox("🖥️ Máy chủ mục tiêu (Host IP)", hosts_list)
            with f_col3:
                ports_list = ["Tất cả"] + [str(p) for p in sorted(df_vulns["port"].dropna().unique().tolist())]
                sel_port = st.selectbox("🔌 Cổng dịch vụ (Port)", ports_list)
            with f_col4:
                sel_sevs = st.multiselect(
                    "⚠️ Mức độ nghiêm trọng",
                    ["Critical", "High", "Medium", "Low", "Info"],
                    default=["Critical", "High", "Medium", "Low", "Info"],
                )

        if sel_host != "Tất cả":
            df_vulns = df_vulns[df_vulns["host_ip"] == sel_host]
        if sel_port != "Tất cả":
            df_vulns = df_vulns[df_vulns["port"].astype(str) == sel_port]
        if sel_sevs:
            df_vulns = df_vulns[df_vulns["severity_label"].isin(sel_sevs)]
        if search_kw.strip():
            kw = search_kw.strip().lower()
            df_vulns = df_vulns[
                df_vulns["plugin_name"].astype(str).str.lower().str.contains(kw, na=False)
                | df_vulns["cve_list"].astype(str).str.lower().str.contains(kw, na=False)
                | df_vulns["plugin_id"].astype(str).str.contains(kw, na=False)
            ]

        # ── Metrics row ──
        total = len(df_vulns)
        critical = len(df_vulns[df_vulns["severity"] == 4])
        high = len(df_vulns[df_vulns["severity"] == 3])
        medium = len(df_vulns[df_vulns["severity"] == 2])
        low = len(df_vulns[df_vulns["severity"] == 1])
        info = len(df_vulns[df_vulns["severity"] == 0])

        m1, m2, m3, m4, m5, m6 = st.columns(6)
        m1.metric("Tổng bản ghi", total)
        m2.metric("🔴 Critical", critical)
        m3.metric("🟠 High", high)
        m4.metric("🟡 Medium", medium)
        m5.metric("🟢 Low", low)
        m6.metric("🔵 Info", info)

        st.divider()

        # ── Charts Row 1 ──
        col_left, col_right = st.columns(2)

        with col_left:
            sev_counts = df_vulns[df_vulns["severity"] > 0]["severity_label"].value_counts()
            if not sev_counts.empty:
                fig_pie = px.pie(
                    names=sev_counts.index,
                    values=sev_counts.values,
                    color=sev_counts.index,
                    color_discrete_map=SEVERITY_COLORS,
                    title="Phân bổ Lỗ hổng Thực tế (Không tính Info)",
                    hole=0.42,
                    template="plotly_white",
                )
                fig_pie.update_layout(paper_bgcolor="#ffffff", plot_bgcolor="#ffffff", font=dict(color="#0f172a"))
                st.plotly_chart(fig_pie, use_container_width=True)
            else:
                st.success("✅ Phiên quét hiện tại không có lỗ hổng từ mức Low trở lên (Chỉ có Info)!")

        with col_right:
            # Ma trận Rủi ro CVSS v3 vs Severity/VPR
            df_risk = df_vulns[df_vulns["severity"] > 0].copy()
            if not df_risk.empty:
                df_risk["cvss3_num"] = pd.to_numeric(df_risk["cvss3_base_score"], errors="coerce").fillna(
                    df_risk["severity"] * 2.2
                )
                df_risk["vpr_estimated"] = (
                    df_risk["cvss3_num"] * 0.85 + df_risk["exploit_available"].astype(int) * 1.2
                ).clip(upper=10.0).round(1)
                fig_matrix = px.scatter(
                    df_risk,
                    x="cvss3_num",
                    y="vpr_estimated",
                    color="severity_label",
                    size="cvss3_num",
                    hover_name="plugin_name",
                    hover_data=["host_ip", "port", "cve_list", "exploit_available"],
                    color_discrete_map=SEVERITY_COLORS,
                    labels={
                        "cvss3_num": "Điểm chuẩn CVSS v3.0 (0 - 10)",
                        "vpr_estimated": "Điểm ưu tiên VPR / Khả năng khai thác (0 - 10)",
                    },
                    title="Ma trận Tương quan Rủi ro (CVSS v3.0 vs. VPR Priority)",
                    template="plotly_white",
                )
                fig_matrix.update_layout(
                    xaxis_range=[0, 10.5],
                    yaxis_range=[0, 10.5],
                    paper_bgcolor="#ffffff",
                    plot_bgcolor="#ffffff",
                    font=dict(color="#0f172a"),
                )
                st.plotly_chart(fig_matrix, use_container_width=True)

        # ── Top lỗ hổng Critical/High/Medium ──
        st.subheader("🔥 Danh sách Lỗ hổng Phát hiện (Sắp xếp theo Mức độ Nguy hiểm)")
        top_vulns = df_vulns.sort_values(
            ["severity", "cvss3_base_score"], ascending=[False, False]
        )

        if not top_vulns.empty:
            display_cols = [c for c in ["host_ip", "port", "protocol", "plugin_id", "plugin_name",
                                         "severity_label", "cvss3_base_score", "cve_list",
                                         "exploit_available"]
                           if c in top_vulns.columns]
            st.dataframe(top_vulns[display_cols], use_container_width=True, hide_index=True)

        # ── Exploitable vulnerabilities ──
        if "exploit_available" in df_vulns.columns:
            exploitable = df_vulns[df_vulns["exploit_available"] == True]
            if not exploitable.empty:
                st.subheader(f"💀 Cảnh báo Đỏ: Lỗ hổng đã có Mã khai thác công khai (Exploit Available: {len(exploitable)})")
                exp_cols = [c for c in ["host_ip", "port", "plugin_id", "plugin_name", "severity_label",
                                         "cvss3_base_score", "cve_list"]
                           if c in exploitable.columns]
                sorted_exp = exploitable.sort_values("severity", ascending=False)
                st.dataframe(sorted_exp[exp_cols], use_container_width=True, hide_index=True)


# ═══════════════════════════════════════════════════════════
#  PAGE: SO SÁNH QUÉT (BLACK-BOX vs WHITE-BOX & BEFORE vs AFTER)
# ═══════════════════════════════════════════════════════════

elif menu == "🔄 So sánh quét":
    st.header("🔄 Đối chiếu Đa kịch bản (Cross-Scan Comparison)")
    st.markdown("""
    Hỗ trợ 2 kịch bản đối chứng cốt lõi của **Phương án A**:
    1. **🕵️ Black-Box (Uncredentialed) vs. White-Box (Credentialed)**: Chứng minh hiệu quả vượt trội khi quét có xác thực SMB/Registry (từ **2 lỗi Medium** vọt lên **47 mục**, phát hiện lỗi **Critical 9.8** & **High 8.8**).
    2. **🔧 Before Patch vs. After Patch (Validation Scan)**: Chứng minh hiệu quả của kịch bản **PowerShell Auto-Remediation** triệt tiêu 100% lỗ hổng và cấp **Chứng chỉ An toàn**.
    """)

    if not st.session_state.db_connected:
        st.warning("⚠️ Cần kết nối database để sử dụng chức năng so sánh.")
    else:
        try:
            from database.crud import get_all_scan_sessions
            from utils.comparator import (
                compare_scans,
                generate_comparison_report_text,
                generate_security_certificate_html,
            )

            sessions = get_all_scan_sessions()
            if len(sessions) < 2:
                st.info("💡 Cần ít nhất 2 phiên quét trong database để so sánh. Hãy nạp thêm phiên quét tại mục **📤 Import Báo cáo**.")
            else:
                compare_mode = st.radio(
                    "🎯 Chọn kịch bản đối chiếu",
                    [
                        "🔧 Trước khi vá (Before Patch) vs. Sau khi vá (After Patch - Validation)",
                        "🕵️ Quét Không xác thực (Black-Box) vs. Quét Có xác thực (White-Box SMB/Registry)",
                    ],
                    horizontal=True,
                )

                is_bb_wb = compare_mode.startswith("🕵️")
                include_info_cmp = st.checkbox(
                    "Tính cả các bản ghi Info (Severity = 0) để đối chiếu tổng số 47 mục White-Box",
                    value=is_bb_wb,
                )

                col_before, col_after = st.columns(2)
                session_ids = sessions["id"].tolist()

                with col_before:
                    before_id = st.selectbox(
                        "📋 Phiên quét 1 (Baseline / Trước vá / Black-Box)",
                        session_ids,
                        format_func=lambda x: f"#{x} - {sessions[sessions['id']==x]['scan_name'].values[0]}",
                        key="compare_before",
                    )
                with col_after:
                    after_id = st.selectbox(
                        "📋 Phiên quét 2 (Đối chứng / Sau vá / White-Box)",
                        session_ids,
                        format_func=lambda x: f"#{x} - {sessions[sessions['id']==x]['scan_name'].values[0]}",
                        key="compare_after",
                        index=min(1, len(session_ids) - 1),
                    )

                if before_id == after_id:
                    st.warning("⚠️ Hãy chọn 2 phiên quét khác nhau.")
                elif st.button("🔍 Thực hiện Đối chiếu & Vẽ Biểu đồ So sánh", type="primary", use_container_width=True):
                    with st.spinner("🔄 Đang phân tích ma trận chênh lệch..."):
                        result = compare_scans(before_id, after_id, include_info=include_info_cmp)
                        summary = result["summary"]
                        before_name = sessions[sessions["id"] == before_id]["scan_name"].values[0]
                        after_name = sessions[sessions["id"] == after_id]["scan_name"].values[0]

                        st.divider()
                        c1, c2, c3, c4, c5 = st.columns(5)
                        c1.metric("📊 Phiên 1", summary["total_before"])
                        c2.metric("📊 Phiên 2", summary["total_after"])
                        c3.metric("✅ Đã khắc phục (Fixed)", summary["total_fixed"], delta=f"-{summary['total_fixed']}", delta_color="normal")
                        c4.metric("🆕 Phát hiện mới (New)", summary["total_new"], delta=f"+{summary['total_new']}", delta_color="inverse")
                        c5.metric("⚠️ Còn tồn tại", summary["total_remaining"])

                        if not is_bb_wb:
                            fix_rate = summary["fix_rate_percent"]
                            st.progress(fix_rate / 100, text=f"🏆 Tỷ lệ khắc phục lỗ hổng (Fix Rate): {fix_rate}%")

                        # ── Biểu đồ cột ghép (Grouped Bar Chart) so sánh theo Severity ──
                        st.subheader("📊 Biểu đồ Đối chiếu Trực quan theo Mức độ Nghiêm trọng")
                        sev_levels = ["Critical", "High", "Medium", "Low"] + (["Info"] if include_info_cmp else [])
                        b_counts = [summary["before_by_severity"].get(s, 0) for s in sev_levels]
                        a_counts = [summary["after_by_severity"].get(s, 0) for s in sev_levels]

                        fig_cmp = go.Figure(data=[
                            go.Bar(name=f"Phiên 1: {before_name[:35]}", x=sev_levels, y=b_counts, marker_color="#ef4444", text=b_counts, textposition="auto"),
                            go.Bar(name=f"Phiên 2: {after_name[:35]}", x=sev_levels, y=a_counts, marker_color="#22c55e", text=a_counts, textposition="auto"),
                        ])
                        fig_cmp.update_layout(
                            barmode="group",
                            title="So sánh số lượng lỗ hổng theo từng cấp độ giữa 2 phiên quét",
                            xaxis_title="Mức độ nghiêm trọng (Severity)",
                            yaxis_title="Số lượng phát hiện",
                            height=400,
                            template="plotly_white",
                            paper_bgcolor="#ffffff",
                            plot_bgcolor="#ffffff",
                            font=dict(color="#0f172a"),
                        )
                        st.plotly_chart(fig_cmp, use_container_width=True)

                        # Tabs chi tiết
                        tab_fixed, tab_new, tab_remain, tab_cert, tab_report = st.tabs([
                            f"✅ Đã khắc phục ({summary['total_fixed']})",
                            f"🆕 Phát hiện mới ({summary['total_new']})",
                            f"⚠️ Còn tồn tại ({summary['total_remaining']})",
                            "🏆 Chứng nhận An toàn (Closed-Loop)",
                            "📄 Báo cáo & Nhận xét AI",
                        ])

                        display_cols_compare = ["host_ip", "port", "plugin_id", "plugin_name",
                                                "severity_label", "cvss3_base_score", "cve_list"]

                        with tab_fixed:
                            df_f = result["fixed"]
                            if not df_f.empty:
                                cols_avail = [c for c in display_cols_compare if c in df_f.columns]
                                st.dataframe(df_f[cols_avail], use_container_width=True, hide_index=True)
                            else:
                                st.info("Không có lỗ hổng nào trong nhóm Fixed.")

                        with tab_new:
                            df_n = result["new"]
                            if not df_n.empty:
                                cols_avail = [c for c in display_cols_compare if c in df_n.columns]
                                st.dataframe(df_n[cols_avail], use_container_width=True, hide_index=True)
                            else:
                                st.success("✅ Không có lỗ hổng mới phát sinh!")

                        with tab_remain:
                            df_r = result["remaining"]
                            if not df_r.empty:
                                cols_avail = [c for c in display_cols_compare if c in df_r.columns]
                                st.dataframe(df_r[cols_avail], use_container_width=True, hide_index=True)
                            else:
                                st.success("✅ Tất cả lỗ hổng mục tiêu đã được triệt tiêu hoàn toàn!")

                        with tab_cert:
                            cert_html = generate_security_certificate_html(
                                result, before_name=before_name, after_name=after_name
                            )
                            st.components.v1.html(cert_html, height=520, scrolling=True)
                            st.download_button(
                                "🏆 Tải Chứng nhận Nghiệm thu An toàn (.html)",
                                cert_html,
                                file_name=f"Security_Clearance_Certificate_{before_id}_vs_{after_id}.html",
                                mime="text/html",
                                type="primary",
                            )

                        with tab_report:
                            report_text = generate_comparison_report_text(result)
                            st.text(report_text)
                            st.download_button(
                                "📥 Tải báo cáo đối chiếu (.txt)",
                                report_text,
                                file_name=f"comparison_{before_id}_vs_{after_id}.txt",
                                mime="text/plain",
                            )
                            if st.session_state.ai_connected:
                                with st.spinner("🤖 AI đang viết nhận xét đánh giá kết quả đối chiếu..."):
                                    try:
                                        from ai_engine.analyzer import generate_comparison_ai_insight
                                        ai_cmp_text = generate_comparison_ai_insight(summary, mode=compare_mode)
                                        st.markdown("### 🧠 Nhận xét Chuyên môn từ AI Security Engine")
                                        st.markdown(ai_cmp_text)
                                    except Exception as e:
                                        st.warning(f"Không thể gọi AI nhận xét: {e}")

        except Exception as e:
            st.error(f"❌ Lỗi: {e}")


# ═══════════════════════════════════════════════════════════
#  PAGE: BẰNG CHỨNG FORENSICS (WIRESHARK & EVENT LOG)
# ═══════════════════════════════════════════════════════════

elif menu == "🔬 Bằng chứng Forensics":
    st.header("🔬 Quản lý Chứng cứ Pháp chứng An ninh (Wireshark & Windows Event Log)")
    st.markdown("""
    Hiện thực hóa **Tính năng 5 (Forensics Evidence Integration)** của Phương án A:
    Đối chiếu lưu lượng gói tin mạng từ **Wireshark** và nhật ký hệ thống từ **Windows Event Viewer** để chứng minh cơ chế hoạt động nội bộ của phiên quét **White-Box (Credentialed Scan)**.
    """)

    f_tab1, f_tab2, f_tab3 = st.tabs([
        "🦈 1. Phân tích Gói tin Wireshark (SMB2 / NTLMSSP / WINREG)",
        "🪟 2. Nhật ký Windows Security Event Log (Event ID 4624 / 4672)",
        "🤖 3. AI Phân tích Tương quan Pháp chứng (DFIR Correlation)",
    ])

    df_ws = pd.DataFrame()
    df_ev = pd.DataFrame()

    with f_tab1:
        st.subheader("🦈 Lưu lượng Bắt tay & Xác thực Nội bộ qua Cổng TCP 445 (Wireshark)")
        st.markdown("""
        - **Bộ lọc Wireshark chuẩn trên card `VMware Network Adapter VMnet8`**:
          ```text
          ip.addr == 192.168.104.129 && (smb2 || ntlmssp || winreg || icmp)
          ```
        """)

        up_pcap_csv = st.file_uploader(
            "📤 Tải lên file CSV xuất từ Wireshark (File → Export Packet Dissections → As CSV):",
            type=["csv"],
            key="wireshark_csv",
        )
        if up_pcap_csv:
            df_ws = pd.read_csv(up_pcap_csv)
            st.dataframe(df_ws, use_container_width=True, hide_index=True)
        else:
            st.info("📭 Chưa có dữ liệu gói tin Wireshark. Hãy tải lên file `.csv` xuất từ Wireshark để hiển thị và phân tích.")

    with f_tab2:
        st.subheader("🪟 Nhật ký Sự kiện Bảo mật Windows (Event Viewer → Security Log)")
        st.markdown("""
        - **Đường dẫn trên máy mục tiêu**: `Event Viewer` $\rightarrow$ `Windows Logs` $\rightarrow$ `Security`.
        - **Các mã sự kiện cần lọc**: `Event ID 4624` (Logon Type 3), `Event ID 4672` (Special Logon), `Event ID 5140` (Share Access).
        """)

        up_evtx_csv = st.file_uploader(
            "📤 Tải lên file CSV xuất từ Windows Event Viewer (Save All Events As → CSV):",
            type=["csv"],
            key="eventlog_csv",
        )
        if up_evtx_csv:
            df_ev = pd.read_csv(up_evtx_csv)
            st.dataframe(df_ev, use_container_width=True, hide_index=True)
        else:
            st.info("📭 Chưa có dữ liệu Windows Event Log. Hãy tải lên file `.csv` xuất từ Event Viewer để hiển thị và phân tích.")

    with f_tab3:
        st.subheader("🤖 AI Phân tích Tương quan Pháp chứng (Wireshark ↔ Event Log ↔ Nessus)")
        if df_ws.empty and df_ev.empty:
            st.info("💡 Vui lòng tải lên ít nhất 1 file CSV ở tab **Wireshark** hoặc **Windows Event Log** trước khi chạy phân tích AI.")
        else:
            if st.button("🧠 Chạy Phân tích Pháp chứng bằng AI", type="primary", use_container_width=True):
                if not st.session_state.ai_connected:
                    st.error("❌ Chưa kết nối AI API.")
                else:
                    with st.spinner("🕵️ AI đang đối chiếu dấu vết gói tin và Event Log..."):
                        try:
                            from ai_engine.analyzer import analyze_forensics_evidence
                            combined_evidence = ""
                            if not df_ws.empty:
                                combined_evidence += "--- WIRESHARK PACKETS ---\n" + df_ws.head(50).to_string(index=False) + "\n\n"
                            if not df_ev.empty:
                                combined_evidence += "--- WINDOWS SECURITY EVENT LOGS ---\n" + df_ev.head(50).to_string(index=False)
                            forensic_report = analyze_forensics_evidence(combined_evidence)
                            st.session_state.forensic_ai_report = forensic_report
                        except Exception as e:
                            st.error(f"❌ Lỗi phân tích Forensics: {e}")

            if "forensic_ai_report" in st.session_state and st.session_state.forensic_ai_report:
                st.markdown(st.session_state.forensic_ai_report)
                st.download_button(
                    "📥 Tải Báo cáo Phân tích Pháp chứng (.md)",
                    st.session_state.forensic_ai_report,
                    file_name="Forensics_Correlation_Report.md",
                    mime="text/markdown",
                )


# ═══════════════════════════════════════════════════════════
#  PAGE: QUẢN LÝ KHẮC PHỤC
# ═══════════════════════════════════════════════════════════

elif menu == "📋 Quản lý khắc phục":
    st.header("📋 Quản lý tiến độ khắc phục")

    if not st.session_state.db_connected:
        st.warning("⚠️ Cần kết nối database để sử dụng chức năng này.")
    else:
        try:
            from database.crud import (
                get_all_scan_sessions,
                get_vulnerabilities_by_session,
                upsert_remediation_status,
                get_remediation_overview,
                get_ai_analysis_by_vuln,
            )

            sessions = get_all_scan_sessions()
            if sessions.empty:
                st.info("💡 Chưa có phiên quét nào.")
            else:
                selected = st.selectbox(
                    "Chọn phiên quét",
                    sessions["id"].tolist(),
                    format_func=lambda x: f"#{x} - {sessions[sessions['id']==x]['scan_name'].values[0]}",
                    key="remediation_session",
                )

                # Tổng quan tiến độ
                overview = get_remediation_overview(selected)
                if not overview.empty:
                    st.subheader("📊 Tổng quan tiến độ")
                    fig_status = px.pie(
                        overview,
                        names="status",
                        values="count",
                        color="status",
                        color_discrete_map={
                            "Open": "#D84315",
                            "In Progress": "#F9A825",
                            "Fixed": "#2E7D32",
                            "Accepted Risk": "#1565C0",
                            "False Positive": "#757575",
                        },
                        hole=0.4,
                        template="plotly_white",
                    )
                    fig_status.update_layout(paper_bgcolor="#ffffff", plot_bgcolor="#ffffff", font=dict(color="#0f172a"))
                    st.plotly_chart(fig_status, use_container_width=True)

                # Danh sách lỗ hổng và cập nhật trạng thái
                st.divider()
                df_vulns = get_vulnerabilities_by_session(selected)
                df_vulns = ensure_vuln_df(df_vulns)
                df_vulns = df_vulns[df_vulns["severity"] > 0]

                if not df_vulns.empty:
                    # Cập nhật hàng loạt (Bulk Update)
                    st.subheader("⚡ Cập nhật nhanh hàng loạt (Sau khi chạy PowerShell Auto-Remediation)")
                    b_col1, b_col2, b_col3 = st.columns([2, 2, 1])
                    with b_col1:
                        bulk_status = st.selectbox(
                            "Trạng thái áp dụng hàng loạt",
                            ["Fixed", "In Progress", "Open", "Accepted Risk"],
                            key="bulk_status_sel",
                        )
                    with b_col2:
                        bulk_assignee = st.text_input("Người thực hiện", value="Admin / AI Auto-Remediation", key="bulk_assign")
                    with b_col3:
                        st.write("")
                        st.write("")
                        if st.button("✅ Áp dụng tất cả", type="primary", use_container_width=True):
                            for _, r in df_vulns.iterrows():
                                vid = r.get("id")
                                if vid:
                                    upsert_remediation_status(int(vid), bulk_status, bulk_assignee)
                            st.success(f"✅ Đã cập nhật toàn bộ {len(df_vulns)} lỗ hổng sang trạng thái '{bulk_status}'!")
                            time.sleep(0.8)
                            st.rerun()

                    st.subheader("🔧 Cập nhật từng lỗ hổng")

                    for _, row in df_vulns.head(50).iterrows():
                        vuln_id = row.get("id")
                        sev_lbl = row.get("severity_label", "Info")
                        p_name = str(row.get("plugin_name", ""))[:80]
                        h_ip = row.get("host_ip", "")
                        p_port = row.get("port", "")
                        with st.expander(
                            f"[{sev_lbl}] {p_name} — {h_ip}:{p_port}"
                        ):
                            rc1, rc2, rc3 = st.columns([2, 2, 1])

                            with rc1:
                                new_status = st.selectbox(
                                    "Trạng thái",
                                    ["Open", "In Progress", "Fixed", "Accepted Risk", "False Positive"],
                                    key=f"status_{vuln_id}",
                                )
                            with rc2:
                                assigned = st.text_input("Giao cho", key=f"assigned_{vuln_id}")
                            with rc3:
                                if st.button("💾 Lưu", key=f"save_{vuln_id}"):
                                    upsert_remediation_status(vuln_id, new_status, assigned or None)
                                    st.success("✅ Đã cập nhật!")

                            # Hiển thị phân tích AI nếu có
                            ai_data = get_ai_analysis_by_vuln(vuln_id)
                            if ai_data:
                                st.markdown("---")
                                st.markdown(f"**🤖 Khắc phục (AI):** {ai_data.get('remediation_steps', 'N/A')[:500]}")
                else:
                    st.success("✅ Không có lỗ hổng nào cần khắc phục (chỉ có Info).")

        except Exception as e:
            st.error(f"❌ Lỗi: {e}")


# ═══════════════════════════════════════════════════════════
#  PAGE: CÀI ĐẶT
# ═══════════════════════════════════════════════════════════

elif menu == "⚙️ Cài đặt":
    st.header("⚙️ Cài đặt & Kiểm tra hệ thống")

    # Thông tin cấu hình hiện tại
    st.subheader("📋 Cấu hình hiện tại")
    config_data = {
        "AI Provider": Settings.AI_PROVIDER,
        "AI Model": Settings.get_model_name(),
        "API Key": ("✅ Đã cấu hình" if Settings.get_active_api_key() else "❌ Chưa có"),
        "DB Server": Settings.DB_SERVER,
        "DB Name": Settings.DB_NAME,
        "DB Auth": "SQL Auth" if Settings.DB_USER else "Windows Auth",
        "ODBC Driver": Settings.DB_DRIVER,
    }
    for k, v in config_data.items():
        st.text(f"  {k:.<25} {v}")

    st.divider()

    # Kiểm tra kết nối
    st.subheader("🔌 Kiểm tra kết nối")

    col_db, col_ai = st.columns(2)

    with col_db:
        st.markdown("#### 🗄️ SQL Server")
        if st.button("Test kết nối DB", use_container_width=True):
            with st.spinner("Đang kiểm tra..."):
                ok, msg = test_connection()
                st.session_state.db_connected = ok
                if ok:
                    st.success(msg)
                else:
                    st.error(msg)

    with col_ai:
        st.markdown("#### 🤖 AI API")
        if st.button("Test kết nối AI", use_container_width=True):
            with st.spinner("Đang kiểm tra..."):
                from ai_engine.analyzer import test_ai_connection
                ok, msg = test_ai_connection()
                st.session_state.ai_connected = ok
                if ok:
                    st.success(msg)
                else:
                    st.error(msg)

    st.divider()

    # Validation
    st.subheader("🔍 Kiểm tra cấu hình")
    errors = Settings.validate()
    if errors:
        for err in errors:
            st.warning(f"⚠️ {err}")
    else:
        st.success("✅ Cấu hình hợp lệ!")

    # Hướng dẫn
    st.divider()
    st.subheader("📖 Hướng dẫn nhanh")
    st.markdown("""
    1. **Sao chép `.env.example` thành `.env`:**
       ```
       copy .env.example .env
       ```
    2. **Điền API Key và cấu hình DB** vào file `.env`.
    3. **Tạo database:**
       ```
       python setup_db.py
       ```
    4. **Chạy ứng dụng:**
       ```
       streamlit run app.py
       ```
    """)
