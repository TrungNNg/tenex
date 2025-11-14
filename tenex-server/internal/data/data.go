package data

import (
	"context"
	"database/sql"
	"errors"
	"time"

	"github.com/google/uuid"
	"github.com/lib/pq"
)

var (
	ErrUsernameAlreadyExist = errors.New("username already exist")
)

type DB struct {
	Users UserModel
	Files FileModel
}

func NewDB(db *sql.DB) *DB {
	q := New(db)
	return &DB{
		Users: UserModel{q: q},
		Files: FileModel{q: q},
	}
}

type UserModel struct {
	q *Queries
}

func (u *UserModel) CreateUser(ctx context.Context, id uuid.UUID, username, password string) (User, error) {
	arg := CreateUserParams{
		ID:        id,
		Username:  username,
		Password:  password,
		CreatedAt: time.Now(),
		UpdatedAt: time.Now(),
	}
	user, err := u.q.CreateUser(ctx, arg)
	if err != nil {
		if pqErr, ok := err.(*pq.Error); ok {
			switch pqErr.Code {
			case "23505":
				return User{}, ErrUsernameAlreadyExist
			}
		}
		return User{}, err
	}
	return user, nil
}

func (u *UserModel) GetUserByUsername(ctx context.Context, username string) (User, error) {
	return u.q.GetUserByUsername(ctx, username)
}

type FileModel struct {
	q *Queries
}

func (f *FileModel) CreateFile(ctx context.Context, userID uuid.UUID, id uuid.UUID, fileName string, data []byte) (File, error) {
	arg := CreateFileParams{
		ID:         id,
		UserID:     userID,
		Filename:   fileName,
		Data:       data,
		UploadedAt: time.Now(),
	}
	return f.q.CreateFile(ctx, arg)
}

func (f *FileModel) DeleteFile(ctx context.Context, fileID uuid.UUID) error {
	return f.q.DeleteFile(ctx, fileID)
}

func (f *FileModel) GetFileByID(ctx context.Context, fileID uuid.UUID, userID uuid.UUID) (File, error) {
	arg := GetFileByIDParams{
		ID:     fileID,
		UserID: userID,
	}
	return f.q.GetFileByID(ctx, arg)
}

func (f *FileModel) GetFilesByUserID(ctx context.Context, userID uuid.UUID) ([]GetFilesByUserIDRow, error) {
	return f.q.GetFilesByUserID(ctx, userID)
}
