-- Prevent duplicate findings within the same scan
-- A finding is unique per scan by: scanner + rule_id + title + file_path + line_number

-- First, remove existing duplicates (keep the first inserted row by id)
DELETE FROM findings f
USING findings f2
WHERE f.scan_id = f2.scan_id
  AND f.scanner = f2.scanner
  AND COALESCE(f.rule_id, '') = COALESCE(f2.rule_id, '')
  AND f.title = f2.title
  AND COALESCE(f.file_path, '') = COALESCE(f2.file_path, '')
  AND COALESCE(f.line_number, 0) = COALESCE(f2.line_number, 0)
  AND f.id > f2.id;

-- Create unique index to prevent future duplicates
CREATE UNIQUE INDEX IF NOT EXISTS idx_findings_unique_per_scan
ON findings (scan_id, scanner, COALESCE(rule_id, ''), title, COALESCE(file_path, ''), COALESCE(line_number, 0));
