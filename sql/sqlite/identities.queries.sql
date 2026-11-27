-- name: CreateIdentity :one
INSERT INTO "identities" (
    "uuid",
    "user_uuid",
    "provider_type",
    "provider",
    "provider_user_id",
    "context_json"
) VALUES (
    ?, ?, ?, ?, ?, ?
)
RETURNING *;

-- name: UpdateIdentityByUUID :one
UPDATE "identities" SET
    "context_json" = ?,
    "user_uuid" = ?
WHERE "uuid" = ?
RETURNING *;

-- name: GetIdentityByProviderIDs :one
SELECT * FROM "identities"
WHERE "provider_type" = ? AND "provider" = ? AND "provider_user_id" = ?;

-- name: GetIdentityByUUID :one
SELECT * FROM "identities"
WHERE "uuid" = ?;
