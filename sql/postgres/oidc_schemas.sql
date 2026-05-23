CREATE TABLE IF NOT EXISTS "oidc_codes" (
    "sub"            TEXT   NOT NULL UNIQUE,
    "code_hash"      TEXT   NOT NULL PRIMARY KEY,
    "scope"          TEXT   NOT NULL,
    "redirect_uri"   TEXT   NOT NULL,
    "client_id"      TEXT   NOT NULL,
    "expires_at"     BIGINT NOT NULL,
    "nonce"          TEXT   NOT NULL DEFAULT '',
    "code_challenge" TEXT   NOT NULL DEFAULT ''
);

CREATE TABLE IF NOT EXISTS "oidc_tokens" (
    "sub"                      TEXT   NOT NULL UNIQUE,
    "access_token_hash"        TEXT   NOT NULL PRIMARY KEY,
    "refresh_token_hash"       TEXT   NOT NULL,
    "code_hash"                TEXT   NOT NULL,
    "scope"                    TEXT   NOT NULL,
    "client_id"                TEXT   NOT NULL,
    "token_expires_at"         BIGINT NOT NULL,
    "refresh_token_expires_at" BIGINT NOT NULL,
    "nonce"                    TEXT   NOT NULL DEFAULT ''
);

CREATE TABLE IF NOT EXISTS "oidc_userinfo" (
    "sub"                TEXT   NOT NULL PRIMARY KEY,
    "name"               TEXT   NOT NULL,
    "preferred_username" TEXT   NOT NULL,
    "email"              TEXT   NOT NULL,
    "groups"             TEXT   NOT NULL,
    "updated_at"         BIGINT NOT NULL,
    "given_name"         TEXT   NOT NULL,
    "family_name"        TEXT   NOT NULL,
    "middle_name"        TEXT   NOT NULL,
    "nickname"           TEXT   NOT NULL,
    "profile"            TEXT   NOT NULL,
    "picture"            TEXT   NOT NULL,
    "website"            TEXT   NOT NULL,
    "gender"             TEXT   NOT NULL,
    "birthdate"          TEXT   NOT NULL,
    "zoneinfo"           TEXT   NOT NULL,
    "locale"             TEXT   NOT NULL,
    "phone_number"       TEXT   NOT NULL,
    "address"            TEXT   NOT NULL
);
