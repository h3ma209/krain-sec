package logging_test

import (
	"encoding/json"
	"os"
	"path/filepath"
	"testing"
	"time"

	"krain-sec/internal/logging"
)

func TestAppLogPersistsJSONL(t *testing.T) {
	dir := t.TempDir()
	t.Setenv("LOG_LEVEL", "info")
	if err := logging.Init(dir); err != nil {
		t.Fatal(err)
	}
	defer logging.Close()

	logging.L().Info("test_event", "k", "v")

	path := logging.Path()
	if path == "" {
		t.Fatal("expected open app path")
	}
	day := time.Now().UTC().Format("2006-01-02")
	want := filepath.Join(dir, "app-"+day+".jsonl")
	if path != want {
		t.Fatalf("path=%q want=%q", path, want)
	}

	raw, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	if len(raw) == 0 {
		t.Fatal("app log empty after write")
	}
	var row map[string]any
	if err := json.Unmarshal(raw[:len(raw)-1], &row); err != nil {
		t.Fatalf("invalid json: %v\n%s", err, raw)
	}
	if row["msg"] != "test_event" || row["k"] != "v" || row["service"] != "krain-sec" {
		t.Fatalf("unexpected row: %#v", row)
	}
}
