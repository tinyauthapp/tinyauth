-- name: CreateSession :one
INSERT INTO "sessions" (
    "uuid",
    "identity_uuid",
    "csrf_token",
    "expires_at",
    "created_at",
    "context_json"
) VALUES (
    $1, $2, $3, $4, $5, $6
)
RETURNING *;

-- name: UpdateSessionByUUID :one
UPDATE "sessions" SET
    "expires_at" = $1,
    "context_json" = $2
WHERE "uuid" = $3
RETURNING *;

-- name: GetSessionByUUID :one
SELECT * FROM "sessions"
WHERE "uuid" = $1;

-- name: DeleteSessionByUUID :exec
DELETE FROM "sessions"
WHERE "uuid" = $1;

-- name: DeleteExpiredSessions :exec
DELETE FROM "sessions"
WHERE "expires_at" < $1;
