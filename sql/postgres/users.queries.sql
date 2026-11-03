-- name: CreateUser :one
INSERT INTO "users" (
    "uuid",
    "username",
    "email",
    "name"
) VALUES (
    $1, $2, $3, $4
)
RETURNING *;

-- name: GetUserByUUID :one
SELECT * FROM "users"
WHERE "uuid" = $1;
