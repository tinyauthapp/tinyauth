CREATE TABLE IF NOT EXISTS "oidc_sessions" (
    "sub" TEXT NOT NULL UNIQUE PRIMARY KEY,
    "access_token_hash" TEXT NOT NULL UNIQUE,
    "refresh_token_hash" TEXT NOT NULL UNIQUE,
    "scope" TEXT NOT NULL,
    "client_id" TEXT NOT NULL,
    "token_expires_at" BIGINT NOT NULL,
    "refresh_token_expires_at" BIGINT NOT NULL,
    "nonce" TEXT NOT NULL DEFAULT '',
    "userinfo_json" TEXT NOT NULL
);

CREATE TABLE IF NOT EXISTS "oidc_consent" (
    "uuid" TEXT NOT NULL UNIQUE PRIMARY KEY,
    "client_id" TEXT NOT NULL,
    "scopes" TEXT NOT NULL,
    "created_at" TIMESTAMP NOT NULL DEFAULT CURRENT_TIMESTAMP,
    "updated_at" TIMESTAMP NOT NULL DEFAULT CURRENT_TIMESTAMP
);
