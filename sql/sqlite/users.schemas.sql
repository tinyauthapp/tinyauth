CREATE TABLE IF NOT EXISTS "users" (
    "uuid" TEXT PRIMARY KEY,
    "username" TEXT NOT NULL,
    "email" TEXT NOT NULL,
    "name" TEXT NOT NULL
);