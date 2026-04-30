ALTER TABLE "sessions" ADD COLUMN "oauth_name" TEXT;

UPDATE "sessions"
SET "oauth_name" = CASE
  WHEN LOWER("provider") = 'github' THEN 'GitHub'
  WHEN LOWER("provider") = 'google' THEN 'Google'
  ELSE UPPER(SUBSTR("provider", 1, 1)) || SUBSTR("provider", 2)
END
WHERE "oauth_name" IS NULL AND "provider" IS NOT NULL;

