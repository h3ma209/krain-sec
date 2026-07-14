package store

import (
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"
)

func TestFileStoreWritesJSONL(t *testing.T) {
	dir := t.TempDir()
	t.Setenv("LOG_DIR", dir)
	t.Setenv("LOG_RETENTION_DAYS", "7")

	if err := InitFromEnv(); err != nil {
		t.Fatal(err)
	}
	t.Cleanup(Close)

	RecordAuthAttempt("http", "1.2.3.4", "admin", "x", false)
	RecordHTTPRequest("GET", "/robots.txt", "1.2.3.4", "curl/8", 200)

	day := time.Now().UTC().Format("2006-01-02")
	eventsPath := filepath.Join(dir, "events-"+day+".jsonl")
	raw, err := os.ReadFile(eventsPath)
	if err != nil {
		t.Fatal(err)
	}
	s := string(raw)
	if !strings.Contains(s, `"type":"auth_attempt"`) || !strings.Contains(s, `"type":"http_request"`) {
		t.Fatalf("unexpected events:\n%s", s)
	}
	if _, err := os.Stat(filepath.Join(dir, "auth-"+day+".jsonl")); err != nil {
		t.Fatal(err)
	}
	if _, err := os.Stat(filepath.Join(dir, "http-"+day+".jsonl")); err != nil {
		t.Fatal(err)
	}
}

func TestPurgeDeletesFilesOlderThanRetention(t *testing.T) {
	dir := t.TempDir()
	t.Setenv("LOG_DIR", dir)
	t.Setenv("LOG_RETENTION_DAYS", "7")

	if err := InitFromEnv(); err != nil {
		t.Fatal(err)
	}
	t.Cleanup(Close)

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

	n, err := purgeOldForTest(time.Now().UTC())
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
