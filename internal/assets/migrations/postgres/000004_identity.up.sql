/*
 Drop the old, legacy, terrible sessions table

 Will log out all users, but that's fine.
 */

DROP TABLE IF EXISTS "sessions";

/*
 The new structure consists of the following:

 Users: holds the user data like the username, password, etc.
 Identities: links the user to the identity provider.
 Sessions: holds the session data like the UUID, CSRF, expiration time, etc.
 */

CREATE TABLE IF NOT EXISTS "users" (
    "uuid" TEXT PRIMARY KEY,
    "username" TEXT NOT NULL,
    "email" TEXT NOT NULL,
    "name" TEXT NOT NULL
);

CREATE TABLE IF NOT EXISTS "identities" (
    "uuid" TEXT PRIMARY KEY,
    "user_uuid" TEXT NOT NULL,
    "provider_type" TEXT NOT NULL,
    "provider" TEXT NOT NULL,
    "provider_user_id" TEXT NOT NULL,
    "context_json" TEXT NOT NULL,
    FOREIGN KEY("user_uuid") REFERENCES "users"("uuid") ON DELETE CASCADE
);

CREATE TABLE IF NOT EXISTS "sessions" (
    "uuid" TEXT PRIMARY KEY,
    "identity_uuid" TEXT NOT NULL,
    "expires_at" BIGINT NOT NULL,
    "created_at" BIGINT NOT NULL,
    "context_json" TEXT NOT NULL,
    FOREIGN KEY("identity_uuid") REFERENCES "identities"("uuid") ON DELETE CASCADE
);