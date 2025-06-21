package db

import (
	"database/sql"
)

type DatabaseProvider interface {
	Connect() error
	Close() error
	Exec(query string, args ...any) (sql.Result, error)
	Query(query string, args ...any) (*sql.Rows, error)
	QueryRow(query string, args ...any) *sql.Row
	Begin() (*sql.Tx, error)
	Commit(tx *sql.Tx) error
	Rollback(tx *sql.Tx) error
}

type Database struct {
	Provider DatabaseProvider
}

func NewDatabase(provider DatabaseProvider) *Database {
	return &Database{Provider: provider}
}

func (db *Database) Connect() error {
	return db.Provider.Connect()
}

func (db *Database) Close() error {
	return db.Provider.Close()
}

func (db *Database) Exec(query string, args ...any) (sql.Result, error) {
	return db.Provider.Exec(query, args...)
}

func (db *Database) Query(query string, args ...any) (*sql.Rows, error) {
	return db.Provider.Query(query, args...)
}

func (db *Database) QueryRow(query string, args ...any) *sql.Row {
	return db.Provider.QueryRow(query, args...)
}

func (db *Database) Begin() (*sql.Tx, error) {
	return db.Provider.Begin()
}

func (db *Database) Commit(tx *sql.Tx) error {
	return db.Provider.Commit(tx)
}

func (db *Database) Rollback(tx *sql.Tx) error {
	return db.Provider.Rollback(tx)
}
