package store_test

import (
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"krain-sec/internal/store"
)

func TestFileStoreWritesJSONL(t *testing.T) {
	dir := initStore(t)

	store.RecordAuthAttempt("http", "1.2.3.4", "admin", "x", false)
	store.RecordHTTPRequest("GET", "/robots.txt", "1.2.3.4", "curl/8", 200)

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
