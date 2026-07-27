-- Preserve the original upload/path basename for UI labels (digest remains content identity).

ALTER TABLE artifacts ADD COLUMN original_file_name TEXT;
