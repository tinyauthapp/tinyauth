CREATE TABLE IF NOT EXISTS "oidc_codes" (
    "sub" TEXT NOT NULL UNIQUE,
    "code_hash" TEXT NOT NULL PRIMARY KEY UNIQUE,
    "scope" TEXT NOT NULL,
    "redirect_uri" TEXT NOT NULL,
    "client_id" TEXT NOT NULL,
    "expires_at" INTEGER NOT NULL
);

CREATE TABLE IF NOT EXISTS "oidc_tokens" (
    "sub" TEXT NOT NULL UNIQUE,
    "access_token_hash" TEXT NOT NULL PRIMARY KEY UNIQUE,
    "refresh_token_hash" TEXT NOT NULL,
    "scope" TEXT NOT NULL,
    "client_id" TEXT NOT NULL,
    "token_expires_at" INTEGER NOT NULL,
    "refresh_token_expires_at" INTEGER NOT NULL
);

CREATE TABLE IF NOT EXISTS "oidc_userinfo" (
    "sub" TEXT NOT NULL UNIQUE PRIMARY KEY,
    "name" TEXT NOT NULL,
    "preferred_username" TEXT NOT NULL,
    "email" TEXT NOT NULL,
    "groups" TEXT NOT NULL,
    "updated_at" INTEGER NOT NULL
);
