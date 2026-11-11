-- ============================================================
--  Nessus AI Analyzer - Database Schema
--  Database: NessusAnalyzer
--  5 bảng chính cho quy trình phân tích lỗ hổng
-- ============================================================

-- 1. SCAN_SESSIONS: Lưu thông tin mỗi phiên quét Nessus
CREATE TABLE scan_sessions (
    id              INT IDENTITY(1,1) PRIMARY KEY,
    scan_name       NVARCHAR(500)   NOT NULL,
    scan_date       DATETIME2       NULL,
    import_date     DATETIME2       NOT NULL DEFAULT GETDATE(),
    source_file     NVARCHAR(1000)  NOT NULL,
    file_type       NVARCHAR(10)    NOT NULL CHECK (file_type IN ('nessus', 'csv')),
    scanner_name    NVARCHAR(255)   NULL,
    policy_name     NVARCHAR(500)   NULL,
    total_hosts     INT             NULL DEFAULT 0,
    total_vulns     INT             NULL DEFAULT 0,
    notes           NVARCHAR(MAX)   NULL
);

-- 2. VULNERABILITIES: Chi tiết từng lỗ hổng phát hiện trong phiên quét
CREATE TABLE vulnerabilities (
    id                  INT IDENTITY(1,1) PRIMARY KEY,
    scan_session_id     INT             NOT NULL,
    host_ip             NVARCHAR(45)    NOT NULL,
    host_name           NVARCHAR(255)   NULL,
    port                INT             NULL,
    protocol            NVARCHAR(10)    NULL,
    service_name        NVARCHAR(100)   NULL,
    plugin_id           INT             NOT NULL,
    plugin_name         NVARCHAR(1000)  NOT NULL,
    plugin_family       NVARCHAR(255)   NULL,
    severity            INT             NOT NULL DEFAULT 0,   -- 0=Info, 1=Low, 2=Medium, 3=High, 4=Critical
    severity_label      NVARCHAR(20)    NULL,
    cvss_base_score     FLOAT           NULL,
    cvss3_base_score    FLOAT           NULL,
    cve_list            NVARCHAR(MAX)   NULL,                 -- Danh sách CVE, phân tách bởi dấu phẩy
    synopsis            NVARCHAR(MAX)   NULL,
    description         NVARCHAR(MAX)   NULL,
    solution            NVARCHAR(MAX)   NULL,                 -- Giải pháp gốc từ Nessus
    plugin_output       NVARCHAR(MAX)   NULL,
    see_also            NVARCHAR(MAX)   NULL,
    exploit_available   BIT             NULL DEFAULT 0,
    exploitability_ease NVARCHAR(255)   NULL,
    patch_pub_date      DATE            NULL,
    vuln_pub_date       DATE            NULL,
    created_at          DATETIME2       NOT NULL DEFAULT GETDATE(),

    CONSTRAINT FK_vuln_session FOREIGN KEY (scan_session_id)
        REFERENCES scan_sessions(id) ON DELETE CASCADE
);

CREATE INDEX IX_vuln_session    ON vulnerabilities(scan_session_id);
CREATE INDEX IX_vuln_severity   ON vulnerabilities(severity DESC);
CREATE INDEX IX_vuln_plugin     ON vulnerabilities(plugin_id);
CREATE INDEX IX_vuln_host       ON vulnerabilities(host_ip);

-- 3. AI_ANALYSES: Kết quả phân tích từ LLM cho mỗi lỗ hổng
CREATE TABLE ai_analyses (
    id                  INT IDENTITY(1,1) PRIMARY KEY,
    vulnerability_id    INT             NOT NULL,
    ai_provider         NVARCHAR(20)    NOT NULL,             -- 'gemini' hoặc 'openai'
    model_name          NVARCHAR(100)   NOT NULL,
    root_cause           NVARCHAR(MAX)   NULL,                -- Nguyên nhân gốc (có bằng chứng)
    risk_explanation    NVARCHAR(MAX)   NULL,                 -- Diễn giải rủi ro dễ hiểu
    remediation_steps   NVARCHAR(MAX)   NULL,                 -- Các bước khắc phục chi tiết
    verification_cmds   NVARCHAR(MAX)   NULL,                 -- Lệnh kiểm tra lại sau khi vá
    priority_score      INT             NULL,                 -- Điểm ưu tiên AI đề xuất (1-10)
    additional_notes    NVARCHAR(MAX)   NULL,
    analyzed_at         DATETIME2       NOT NULL DEFAULT GETDATE(),

    CONSTRAINT FK_analysis_vuln FOREIGN KEY (vulnerability_id)
        REFERENCES vulnerabilities(id) ON DELETE CASCADE
);

CREATE INDEX IX_analysis_vuln ON ai_analyses(vulnerability_id);

-- 4. REMEDIATION_TRACKING: Theo dõi tiến độ khắc phục từng lỗ hổng
CREATE TABLE remediation_tracking (
    id                  INT IDENTITY(1,1) PRIMARY KEY,
    vulnerability_id    INT             NOT NULL,
    status              NVARCHAR(30)    NOT NULL DEFAULT 'Open'
                        CHECK (status IN ('Open', 'In Progress', 'Fixed', 'Accepted Risk', 'False Positive')),
    assigned_to         NVARCHAR(255)   NULL,
    started_at          DATETIME2       NULL,
    resolved_at         DATETIME2       NULL,
    resolution_note     NVARCHAR(MAX)   NULL,
    updated_at          DATETIME2       NOT NULL DEFAULT GETDATE(),

    CONSTRAINT FK_tracking_vuln FOREIGN KEY (vulnerability_id)
        REFERENCES vulnerabilities(id) ON DELETE CASCADE
);

CREATE INDEX IX_tracking_vuln   ON remediation_tracking(vulnerability_id);
CREATE INDEX IX_tracking_status ON remediation_tracking(status);

-- 5. SCAN_COMPARISONS: So sánh giữa 2 phiên quét (trước/sau khắc phục)
CREATE TABLE scan_comparisons (
    id                  INT IDENTITY(1,1) PRIMARY KEY,
    scan_before_id      INT             NOT NULL,
    scan_after_id       INT             NOT NULL,
    compared_at         DATETIME2       NOT NULL DEFAULT GETDATE(),
    total_fixed         INT             NOT NULL DEFAULT 0,
    total_new           INT             NOT NULL DEFAULT 0,
    total_remaining     INT             NOT NULL DEFAULT 0,
    summary_json        NVARCHAR(MAX)   NULL,                 -- JSON chi tiết kết quả so sánh
    notes               NVARCHAR(MAX)   NULL,

    CONSTRAINT FK_compare_before FOREIGN KEY (scan_before_id)
        REFERENCES scan_sessions(id),
    CONSTRAINT FK_compare_after  FOREIGN KEY (scan_after_id)
        REFERENCES scan_sessions(id)
);

CREATE INDEX IX_compare_before ON scan_comparisons(scan_before_id);
CREATE INDEX IX_compare_after  ON scan_comparisons(scan_after_id);
