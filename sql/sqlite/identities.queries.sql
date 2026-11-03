-- name: CreateIdentity :one
INSERT INTO "identities" (
    "uuid",
    "user_uuid",
    "provider",
    "provider_user_id",
    "context_json"
) VALUES (
    ?, ?, ?, ?, ?
)
RETURNING *;

-- name: GetIdentityByUUID :one
SELECT * FROM "identities"
WHERE "uuid" = ?;
