package store

import (
	"context"
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"strconv"
	"sync"
	"time"

	"github.com/golang/glog"
)

var (
	mu        sync.Mutex
	logDir    string
	retention time.Duration
	dayStamp  string // UTC YYYY-MM-DD currently open
	writers   map[string]*os.File
)

// InitFromEnv creates LOG_DIR and opens today's JSONL files.
// LOG_RETENTION_DAYS (default 7) controls how long files are kept.
func InitFromEnv() error {
	mu.Lock()
	defer mu.Unlock()
	return initLocked()
}

func initLocked() error {
	dir := envOr("LOG_DIR", "logs")
	if logDir == dir && writers != nil && writers["events"] != nil {
		return nil
	}
	closeAllLocked()

	if err := os.MkdirAll(dir, 0o755); err != nil {
		return fmt.Errorf("mkdir log dir: %w", err)
	}

	days := 7
	if v := os.Getenv("LOG_RETENTION_DAYS"); v != "" {
		n, err := strconv.Atoi(v)
		if err != nil || n < 1 {
			return fmt.Errorf("LOG_RETENTION_DAYS must be >= 1, got %q", v)
		}
		days = n
	}
	retention = time.Duration(days) * 24 * time.Hour
	logDir = dir
	writers = make(map[string]*os.File)
	dayStamp = time.Now().UTC().Format("2006-01-02")
	if err := openDayLocked(dayStamp); err != nil {
		return err
	}

	n, err := purgeOldLocked(time.Now().UTC())
	if err != nil {
		glog.Warningf("log retention: initial purge: %v", err)
	} else if n > 0 {
		glog.Infof("log retention: deleted %d file(s) older than %d day(s)", n, days)
	}
	glog.Infof("file store: writing under %s (retain %d days)", logDir, days)
	return nil
}

// StartRetention runs hourly cleanup until ctx is cancelled. Call after InitFromEnv.
func StartRetention(ctx context.Context) {
	go func() {
		t := time.NewTicker(time.Hour)
		defer t.Stop()
		for {
			select {
			case <-ctx.Done():
				return
			case <-t.C:
				mu.Lock()
				n, err := purgeOldLocked(time.Now().UTC())
				mu.Unlock()
				if err != nil {
					glog.Warningf("log retention: %v", err)
				} else if n > 0 {
					glog.Infof("log retention: deleted %d file(s)", n)
				}
			}
		}
	}()
}

// LogDir returns the configured directory (empty before Init).
func LogDir() string { return logDir }

func Close() {
	mu.Lock()
	defer mu.Unlock()
	closeAllLocked()
}

func closeAllLocked() {
	for k, f := range writers {
		_ = f.Close()
		delete(writers, k)
	}
}

func openAppend(path string) (*os.File, error) {
	return os.OpenFile(path, os.O_CREATE|os.O_WRONLY|os.O_APPEND, 0o644)
}

func envOr(k, def string) string {
	if v := os.Getenv(k); v != "" {
		return v
	}
	return def
}

func dayFile(base, day string) string {
	return fmt.Sprintf("%s-%s.jsonl", base, day)
}

func openDayLocked(day string) error {
	closeAllLocked()
	bases := []string{"events", "auth", "http", "ssh", "honeytoken", "webrtc", "decoy"}
	for _, base := range bases {
		name := dayFile(base, day)
		f, err := openAppend(filepath.Join(logDir, name))
		if err != nil {
			closeAllLocked()
			return fmt.Errorf("open %s: %w", name, err)
		}
		writers[base] = f
	}
	dayStamp = day
	return nil
}

func ensureDayLocked() error {
	today := time.Now().UTC().Format("2006-01-02")
	if today == dayStamp && writers["events"] != nil {
		return nil
	}
	return openDayLocked(today)
}

// purgeOldLocked removes files in logDir whose mtime is older than retention.
// Skips directories and currently-open writers for today.
func purgeOldLocked(now time.Time) (int, error) {
	if logDir == "" || retention <= 0 {
		return 0, nil
	}
	cutoff := now.Add(-retention)
	entries, err := os.ReadDir(logDir)
	if err != nil {
		return 0, err
	}

	openPaths := make(map[string]struct{})
	for _, f := range writers {
		if f != nil {
			openPaths[f.Name()] = struct{}{}
		}
	}

	deleted := 0
	for _, e := range entries {
		if e.IsDir() {
			continue
		}
		path := filepath.Join(logDir, e.Name())
		if _, open := openPaths[path]; open {
			continue
		}
		// Skip live glog symlink (krain-sec.INFO etc.)
		if e.Type()&os.ModeSymlink != 0 {
			continue
		}
		info, err := e.Info()
		if err != nil {
			continue
		}
		if !info.ModTime().Before(cutoff) {
			continue
		}
		if err := os.Remove(path); err != nil {
			glog.Warningf("log retention: remove %s: %v", path, err)
			continue
		}
		deleted++
	}
	return deleted, nil
}

func writeEvent(kind, base string, fields map[string]any) {
	mu.Lock()
	defer mu.Unlock()
	if logDir == "" {
		return
	}
	if err := ensureDayLocked(); err != nil {
		glog.Warningf("log rotate day: %v", err)
		return
	}

	payload := map[string]any{
		"ts":   time.Now().UTC().Format(time.RFC3339Nano),
		"type": kind,
	}
	for k, v := range fields {
		payload[k] = v
	}
	b, err := json.Marshal(payload)
	if err != nil {
		glog.Warningf("log marshal: %v", err)
		return
	}
	b = append(b, '\n')

	writeFileLocked("events", b)
	writeFileLocked(base, b)
}

func writeFileLocked(base string, b []byte) {
	f := writers[base]
	if f == nil {
		glog.Warningf("log writer missing: %s", base)
		return
	}
	if _, err := f.Write(b); err != nil {
		glog.Warningf("log write %s: %v", base, err)
		return
	}
	_ = f.Sync()
}

func RecordAuthAttempt(service, srcIP, username, password string, success bool) {
	writeEvent("auth_attempt", "auth", map[string]any{
		"service":  service,
		"src_ip":   srcIP,
		"username": username,
		"password": password,
		"success":  success,
	})
}

func RecordSSHCommand(srcIP, username, command string) {
	writeEvent("ssh_command", "ssh", map[string]any{
		"src_ip":   srcIP,
		"username": username,
		"command":  command,
	})
}

func RecordHoneytokenHit(tokenID, kind, srcIP, detail string) {
	writeEvent("honeytoken_hit", "honeytoken", map[string]any{
		"token_id": tokenID,
		"kind":     kind,
		"src_ip":   srcIP,
		"detail":   truncate(detail, 512),
	})
}

func RecordHTTPRequest(method, path, srcIP, userAgent string, status int) {
	writeEvent("http_request", "http", map[string]any{
		"method":      method,
		"path":        path,
		"src_ip":      srcIP,
		"user_agent":  truncate(userAgent, 512),
		"status_code": status,
	})
}

func RecordWebRTCLeak(srcIP, address, payload string) {
	writeEvent("webrtc_leak", "webrtc", map[string]any{
		"src_ip":  srcIP,
		"address": address,
		"payload": truncate(payload, 2048),
	})
}

func RecordDecoy(service, srcIP, detail string) {
	writeEvent("decoy", "decoy", map[string]any{
		"service": service,
		"src_ip":  srcIP,
		"detail":  truncate(detail, 512),
	})
}

func truncate(s string, n int) string {
	if len(s) <= n {
		return s
	}
	return s[:n]
}

// purgeOldForTest exposes retention delete for tests.
func purgeOldForTest(now time.Time) (int, error) {
	mu.Lock()
	defer mu.Unlock()
	return purgeOldLocked(now)
}
