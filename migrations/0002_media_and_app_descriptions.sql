ALTER TABLE users ADD COLUMN avatar_key TEXT;
ALTER TABLE users ADD COLUMN avatar_color TEXT NOT NULL DEFAULT '';
ALTER TABLE users ADD COLUMN avatar_version INTEGER NOT NULL DEFAULT 0;

UPDATE users
SET avatar_color = CASE abs(random()) % 8
  WHEN 0 THEN '#dbeafe'
  WHEN 1 THEN '#dcfce7'
  WHEN 2 THEN '#fae8ff'
  WHEN 3 THEN '#fef3c7'
  WHEN 4 THEN '#ffe4e6'
  WHEN 5 THEN '#e0e7ff'
  WHEN 6 THEN '#ccfbf1'
  ELSE '#ffedd5'
END
WHERE avatar_color = '';

ALTER TABLE apps ADD COLUMN logo_key TEXT;
ALTER TABLE apps ADD COLUMN logo_version INTEGER NOT NULL DEFAULT 0;
ALTER TABLE apps ADD COLUMN privilege_description TEXT NOT NULL DEFAULT '';
