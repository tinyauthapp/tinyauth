/*
This migration will nuke the entire setup of OIDC sessions and merge everything
into one table.
*/

/*
Drop all the old tables. Yes, we will log out all OIDC users, but not really a big deal
*/

DROP TABLE IF EXISTS "oidc_tokens";
DROP TABLE IF EXISTS "oidc_userinfo";
DROP TABLE IF EXISTS "oidc_codes";

/*
Create a new simple OIDC sessions table that will hold tokens + userinfo.
*/

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
