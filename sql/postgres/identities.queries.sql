-- name: CreateIdentity :one
INSERT INTO "identities" (
    "uuid",
    "user_uuid",
    "provider",
    "provider_user_id",
    "context_json"
) VALUES (
    $1, $2, $3, $4, $5
)
RETURNING *;

-- name: GetIdentityByUUID :one
SELECT * FROM "identities"
WHERE "uuid" = $1;
