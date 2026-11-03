CREATE TABLE IF NOT EXISTS "identities" (
    "uuid" TEXT PRIMARY KEY,
    "user_uuid" TEXT NOT NULL,
    "provider" TEXT NOT NULL,
    "provider_user_id" TEXT NOT NULL,
    "context_json" TEXT NOT NULL,
    FOREIGN KEY("user_uuid") REFERENCES "users"("uuid") ON DELETE CASCADE
);