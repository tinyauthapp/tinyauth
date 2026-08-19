CREATE TABLE IF NOT EXISTS "sessions" (
    "uuid"         TEXT    NOT NULL PRIMARY KEY,
    "username"     TEXT    NOT NULL,
    "email"        TEXT    NOT NULL,
    "name"         TEXT    NOT NULL,
    "provider"     TEXT    NOT NULL,
    "totp_pending" BOOLEAN NOT NULL,
    "oauth_groups" TEXT    NOT NULL DEFAULT '',
    "expiry"       BIGINT  NOT NULL,
    "created_at"   BIGINT  NOT NULL,
    "oauth_name"   TEXT    NOT NULL DEFAULT '',
    "oauth_sub"    TEXT    NOT NULL DEFAULT ''
);
