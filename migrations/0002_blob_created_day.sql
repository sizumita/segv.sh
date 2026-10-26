-- The blob registry is NOT public data and cannot be rebuilt from the log (blob ids, sizes and upload
-- times never appear in it). A millisecond upload time could be matched to the kind-4 row appended right
-- after the upload, marking that row as an image message: keep only the UTC day (ms at 00:00:00Z).
UPDATE blobs SET created_at = created_at - (created_at % 86400000);
