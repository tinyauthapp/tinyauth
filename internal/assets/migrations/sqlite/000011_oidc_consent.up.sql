CREATE TABLE IF NOT EXISTS "oidc_consents" (
    "username" TEXT NOT NULL,
    "client_id" TEXT NOT NULL,
    "scope" TEXT NOT NULL,
    "created_at" INTEGER NOT NULL,
    PRIMARY KEY ("username", "client_id")
);
