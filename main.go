package main

import (
	"fmt"
	"log"

	"github.com/david22573/envspace/db"
)

func main() {
	sqlite := db.NewSqliteDB("file:test.db?cache=shared&mode=memory")
	database := db.NewDatabase(sqlite)

	if err := database.Connect(); err != nil {
		log.Fatalf("Failed to connect: %v", err)
	}
	defer database.Close()

	_, err := database.Exec(`CREATE TABLE IF NOT EXISTS users (id INTEGER PRIMARY KEY, name TEXT)`)
	if err != nil {
		log.Fatalf("Failed to create table: %v", err)
	}

	_, err = database.Exec(`INSERT INTO users (name) VALUES (?)`, "Alice")
	if err != nil {
		log.Fatalf("Failed to insert: %v", err)
	}

	row := database.QueryRow(`SELECT name FROM users WHERE id = ?`, 1)
	var name string
	if err := row.Scan(&name); err != nil {
		log.Fatalf("Failed to scan: %v", err)
	}

	fmt.Println("User name:", name)
}
