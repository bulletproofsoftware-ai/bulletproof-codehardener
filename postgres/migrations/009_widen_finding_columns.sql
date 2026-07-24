-- Widen findings VARCHAR columns to prevent truncation on large scan results
-- Trivy/Grype produce long titles/file paths; Opengrep/Semgrep return full CWE title strings
-- (e.g. "CWE-79: Improper Neutralization of Input During Web Page Generation")
-- which exceed VARCHAR(20). Convert all to TEXT to avoid future truncation.
ALTER TABLE findings ALTER COLUMN title TYPE TEXT;
ALTER TABLE findings ALTER COLUMN file_path TYPE TEXT;
ALTER TABLE findings ALTER COLUMN rule_id TYPE TEXT;
ALTER TABLE findings ALTER COLUMN cwe_id TYPE TEXT;
ALTER TABLE findings ALTER COLUMN owasp_category TYPE TEXT;
ALTER TABLE findings ALTER COLUMN scanner TYPE TEXT;
ALTER TABLE findings ALTER COLUMN tool_name TYPE TEXT;
ALTER TABLE findings ALTER COLUMN severity TYPE TEXT;
ALTER TABLE findings ALTER COLUMN status TYPE TEXT;
