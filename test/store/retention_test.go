package store_test

import (
	"os"
	"path/filepath"
	"testing"
	"time"

	"krain-sec/internal/store"
)

func TestPurgeDeletesFilesOlderThanRetention(t *testing.T) {
	dir := initStore(t)

	oldPath := filepath.Join(dir, "events-2000-01-01.jsonl")
	if err := os.WriteFile(oldPath, []byte("{}\n"), 0o644); err != nil {
		t.Fatal(err)
	}
	oldTime := time.Now().Add(-8 * 24 * time.Hour)
	if err := os.Chtimes(oldPath, oldTime, oldTime); err != nil {
		t.Fatal(err)
	}

	freshPath := filepath.Join(dir, "events-keep.jsonl")
	if err := os.WriteFile(freshPath, []byte("{}\n"), 0o644); err != nil {
		t.Fatal(err)
	}

	n, err := store.PurgeOldForTest(time.Now().UTC())
	if err != nil {
		t.Fatal(err)
	}
	if n < 1 {
		t.Fatalf("expected at least 1 deletion, got %d", n)
	}
	if _, err := os.Stat(oldPath); !os.IsNotExist(err) {
		t.Fatalf("old file still present")
	}
	if _, err := os.Stat(freshPath); err != nil {
		t.Fatalf("fresh file should remain: %v", err)
	}
}
