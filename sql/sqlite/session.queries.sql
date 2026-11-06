-- name: CreateSession :one
INSERT INTO "sessions" (
    "uuid",
    "identity_uuid",
    "csrf_token",
    "expires_at",
    "created_at",
    "context_json"
) VALUES (
    ?, ?, ?, ?, ?, ?
)
RETURNING *;

-- name: UpdateSessionByUUID :one
UPDATE "sessions" SET
    "expires_at" = ?,
    "context_json" = ?
WHERE "uuid" = ?
RETURNING *;

-- name: GetSessionByUUID :one
SELECT * FROM "sessions"
WHERE "uuid" = ?;

-- name: DeleteSessionByUUID :exec
DELETE FROM "sessions"
WHERE "uuid" = ?;

-- name: DeleteExpiredSessions :exec
DELETE FROM "sessions"
WHERE "expires_at" < ?;
