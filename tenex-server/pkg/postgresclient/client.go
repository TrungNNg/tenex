package postgresclient

import (
	"context"
	"database/sql"
	"log/slog"
	"os"
	"time"

	_ "github.com/lib/pq"
	"github.com/pressly/goose"
)

const (
	DB = "postgres"
)

type PostgresConfig struct {
	DSN         string
	MaxOpenConn int
	MaxIdelConn int
	MaxIdleTime int
}

func New(cfg PostgresConfig) *sql.DB {
	db, err := sql.Open(DB, cfg.DSN)
	if err != nil {
		slog.Info(err.Error())
		slog.Error("could not connect to postgres")
		os.Exit(1)
	}
	db.SetMaxOpenConns(cfg.MaxOpenConn)
	db.SetMaxIdleConns(cfg.MaxIdelConn)
	db.SetConnMaxIdleTime(time.Duration(cfg.MaxIdleTime) * time.Minute)

	// check postgres connection
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	err = db.PingContext(ctx)
	if err != nil {
		slog.Error("could not ping postgres client")
		os.Exit(1)
	}

	// Run migrations
	if err := goose.SetDialect("postgres"); err != nil {
		slog.Error("could not set goose dialect", "error", err)
		os.Exit(1)
	}

	if err := goose.Up(db, "./sql/schema"); err != nil {
		slog.Error("could not run migrations", "error", err)
		os.Exit(1)
	}

	slog.Info("migrations completed successfully")

	return db
}
