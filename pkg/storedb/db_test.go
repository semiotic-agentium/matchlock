package storedb

import (
	"path/filepath"
	"testing"

	"github.com/stretchr/testify/require"
)

func TestOpen_AppliesMigrations(t *testing.T) {
	dbPath := filepath.Join(t.TempDir(), "meta.db")
	db, err := Open(OpenOptions{
		Path:   dbPath,
		Module: "state",
		Migrations: []Migration{
			{
				Version: 1,
				Name:    "create_test_table",
				SQL:     `CREATE TABLE IF NOT EXISTS test_table (id TEXT PRIMARY KEY)`,
			},
		},
	})
	require.NoError(t, err)
	defer db.Close()

	var count int
	require.NoError(t, db.QueryRow(`SELECT COUNT(*) FROM schema_migrations WHERE module = ?`, "state").Scan(&count))
	require.Equal(t, 1, count)
}

func TestOpen_RestoresBackupOnMigrationFailure(t *testing.T) {
	dbPath := filepath.Join(t.TempDir(), "meta.db")

	// Seed the DB with an initial successful migration so rollback has state to preserve.
	db, err := Open(OpenOptions{
		Path:   dbPath,
		Module: "state",
		Migrations: []Migration{
			{
				Version: 1,
				Name:    "create_seed_table",
				SQL:     `CREATE TABLE IF NOT EXISTS seed (id TEXT PRIMARY KEY)`,
			},
		},
	})
	require.NoError(t, err)
	require.NoError(t, db.Close())

	_, err = Open(OpenOptions{
		Path:   dbPath,
		Module: "state",
		Migrations: []Migration{
			{
				Version: 1,
				Name:    "create_seed_table",
				SQL:     `CREATE TABLE IF NOT EXISTS seed (id TEXT PRIMARY KEY)`,
			},
			{
				Version: 2,
				Name:    "broken_sql",
				SQL:     `THIS IS INVALID SQL`,
			},
		},
	})
	require.Error(t, err)

	// Reopen with only valid migration set; version 2 should not be marked applied.
	db, err = Open(OpenOptions{
		Path:   dbPath,
		Module: "state",
		Migrations: []Migration{
			{
				Version: 1,
				Name:    "create_seed_table",
				SQL:     `CREATE TABLE IF NOT EXISTS seed (id TEXT PRIMARY KEY)`,
			},
		},
	})
	require.NoError(t, err)
	defer db.Close()

	var count int
	require.NoError(t, db.QueryRow(`SELECT COUNT(*) FROM schema_migrations WHERE module = ?`, "state").Scan(&count))
	require.Equal(t, 1, count)
}
