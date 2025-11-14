-- name: CreateFile :one
INSERT INTO files (
    id,
    user_id,
    filename,
    data,
    uploaded_at
) VALUES (
    $1, $2, $3, $4, $5
)
RETURNING *;

-- name: GetFileByID :one
SELECT * FROM files
WHERE id = $1 AND user_id = $2;

-- name: GetFilesByUserID :many
SELECT 
    id,
    filename,
    uploaded_at
FROM files
WHERE user_id = $1
ORDER BY uploaded_at DESC;

-- name: DeleteFile :exec
DELETE FROM files
WHERE id = $1;