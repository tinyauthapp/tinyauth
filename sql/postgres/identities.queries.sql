-- name: CreateIdentity :one
INSERT INTO "identities" (
    "uuid",
    "user_uuid",
    "provider_type",
    "provider",
    "provider_user_id",
    "context_json"
) VALUES (
    $1, $2, $3, $4, $5, $6
)
RETURNING *;

-- name: UpdateIdentityByUUID :one
UPDATE "identities" SET
    "context_json" = $1,
    "user_uuid" = $2
WHERE "uuid" = $3
RETURNING *;

-- name: GetIdentityByProviderIDs :one
SELECT * FROM "identities"
WHERE "provider_type" = $1 AND "provider" = $2 AND "provider_user_id" = $3;

-- name: GetIdentityByUUID :one
SELECT * FROM "identities"
WHERE "uuid" = $1;
