CREATE TABLE IF NOT EXISTS "sessions" (
    "uuid" TEXT NOT NULL PRIMARY KEY UNIQUE,
    "username" TEXT NOT NULL,
    "email" TEXT NOT NULL,
    "name" TEXT NOT NULL,
    "provider" TEXT NOT NULL,
    "totp_pending" BOOLEAN NOT NULL,
    "oauth_groups" TEXT NULL,
    "expiry" INTEGER NOT NULL
);