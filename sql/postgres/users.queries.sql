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

-- name: GetUserByUsername :one
SELECT * FROM "users"
WHERE "username" = $1;

-- name: GetUserByEmail :one
SELECT * FROM "users"
WHERE "email" = $1;

-- name: GetUserByUsernameAndEmail :one
SELECT * FROM "users"
WHERE "username" = $1 AND "email" = $2;

-- name: UpdateUser :exec
UPDATE "users" SET
    "username" = $1,
    "email" = $2,
    "name" = $3
WHERE "uuid" = $4;