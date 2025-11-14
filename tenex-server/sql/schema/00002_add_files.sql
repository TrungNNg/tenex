-- +goose Up
CREATE TABLE IF NOT EXISTS files (
    id UUID PRIMARY KEY,
    user_id UUID NOT NULL REFERENCES users(id),
    filename TEXT NOT NULL,
    data BYTEA NOT NULL,
    uploaded_at TIMESTAMP NOT NULL
);

-- +goose Down
DROP TABLE files;