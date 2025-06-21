package db

import (
	"database/sql"
	"fmt"

	_ "modernc.org/sqlite" // or "_ github.com/mattn/go-sqlite3" if CGO is acceptable
)

type SqliteDB struct {
	dsn string
	db  *sql.DB
}

func NewSqliteDB(dsn string) *SqliteDB {
	return &SqliteDB{dsn: dsn}
}

func (s *SqliteDB) Connect() error {
	db, err := sql.Open("sqlite", s.dsn)
	if err != nil {
		return fmt.Errorf("failed to open SQLite DB: %w", err)
	}
	if err := db.Ping(); err != nil {
		return fmt.Errorf("failed to ping SQLite DB: %w", err)
	}
	s.db = db
	return nil
}

func (s *SqliteDB) Close() error {
	if s.db != nil {
		return s.db.Close()
	}
	return nil
}

func (s *SqliteDB) Exec(query string, args ...any) (sql.Result, error) {
	return s.db.Exec(query, args...)
}

func (s *SqliteDB) Query(query string, args ...any) (*sql.Rows, error) {
	return s.db.Query(query, args...)
}

func (s *SqliteDB) QueryRow(query string, args ...any) *sql.Row {
	return s.db.QueryRow(query, args...)
}

func (s *SqliteDB) Begin() (*sql.Tx, error) {
	return s.db.Begin()
}

func (s *SqliteDB) Commit(tx *sql.Tx) error {
	if tx == nil {
		return nil
	}
	return tx.Commit()
}

func (s *SqliteDB) Rollback(tx *sql.Tx) error {
	if tx == nil {
		return nil
	}
	return tx.Rollback()
}
