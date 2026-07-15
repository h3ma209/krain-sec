package store_test

import (
	"testing"

	"krain-sec/internal/store"
)

func initStore(t *testing.T) string {
	t.Helper()
	dir := t.TempDir()
	t.Setenv("LOG_DIR", dir)
	t.Setenv("LOG_RETENTION_DAYS", "7")
	if err := store.InitFromEnv(); err != nil {
		t.Fatal(err)
	}
	t.Cleanup(store.Close)
	return dir
}
