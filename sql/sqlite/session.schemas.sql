CREATE TABLE IF NOT EXISTS "sessions" (
    "uuid" TEXT PRIMARY KEY,
    "identity_uuid" TEXT NOT NULL,
    "expires_at" INTEGER NOT NULL,
    "created_at" INTEGER NOT NULL,
    "context_json" TEXT NOT NULL,
    FOREIGN KEY("identity_uuid") REFERENCES "identities"("uuid") ON DELETE CASCADE
);