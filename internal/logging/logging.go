package logging

import (
	"fmt"
	"io"
	"log/slog"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"time"
)

var (
	mu      sync.Mutex
	logger  *slog.Logger
	appFile *dayFile
)

// Init sets the default slog logger to JSON (stdout + LOG_DIR/app-YYYY-MM-DD.jsonl).
// App file rotates at UTC midnight and Syncs after every write.
func Init(logDir string) error {
	mu.Lock()
	defer mu.Unlock()

	level := slog.LevelInfo
	switch strings.ToLower(os.Getenv("LOG_LEVEL")) {
	case "debug":
		level = slog.LevelDebug
	case "warn", "warning":
		level = slog.LevelWarn
	case "error":
		level = slog.LevelError
	}

	opts := &slog.HandlerOptions{
		Level: level,
		ReplaceAttr: func(_ []string, a slog.Attr) slog.Attr {
			switch a.Key {
			case slog.TimeKey:
				return slog.String("ts", a.Value.Time().UTC().Format(time.RFC3339Nano))
			case slog.MessageKey:
				return slog.String("msg", a.Value.String())
			case slog.LevelKey:
				lvl := a.Value.Any().(slog.Level)
				name := "info"
				switch {
				case lvl >= slog.LevelError:
					name = "error"
				case lvl >= slog.LevelWarn:
					name = "warn"
				case lvl >= slog.LevelInfo:
					name = "info"
				default:
					name = "debug"
				}
				return slog.String("level", name)
			}
			return a
		},
	}

	writers := []io.Writer{os.Stdout}
	if logDir != "" {
		if err := os.MkdirAll(logDir, 0o755); err != nil {
			return fmt.Errorf("mkdir log dir: %w", err)
		}
		df, err := openDayFile(logDir, "app")
		if err != nil {
			return err
		}
		if appFile != nil {
			_ = appFile.Close()
		}
		appFile = df
		writers = append(writers, df)
	}

	h := slog.NewJSONHandler(io.MultiWriter(writers...), opts)
	logger = slog.New(h).With("service", "krain-sec")
	slog.SetDefault(logger)
	return nil
}

// Close flushes and closes the app log file.
func Close() {
	mu.Lock()
	defer mu.Unlock()
	if appFile != nil {
		_ = appFile.Close()
		appFile = nil
	}
}

// Path returns the current open app log path (empty if none).
func Path() string {
	mu.Lock()
	defer mu.Unlock()
	if appFile == nil {
		return ""
	}
	return appFile.path()
}

// L returns the process logger.
func L() *slog.Logger {
	if logger != nil {
		return logger
	}
	return slog.Default()
}

// dayFile appends JSONL lines, Syncs each write, rotates on UTC day change.
type dayFile struct {
	mu     sync.Mutex
	dir    string
	prefix string
	day    string
	f      *os.File
}

func openDayFile(dir, prefix string) (*dayFile, error) {
	df := &dayFile{dir: dir, prefix: prefix}
	if err := df.ensureLocked(time.Now().UTC()); err != nil {
		return nil, err
	}
	return df, nil
}

func (d *dayFile) path() string {
	d.mu.Lock()
	defer d.mu.Unlock()
	if d.f == nil {
		return ""
	}
	return d.f.Name()
}

func (d *dayFile) Write(p []byte) (int, error) {
	d.mu.Lock()
	defer d.mu.Unlock()
	if err := d.ensureLocked(time.Now().UTC()); err != nil {
		return 0, err
	}
	n, err := d.f.Write(p)
	if err != nil {
		return n, err
	}
	if err := d.f.Sync(); err != nil {
		return n, err
	}
	return n, nil
}

func (d *dayFile) Close() error {
	d.mu.Lock()
	defer d.mu.Unlock()
	if d.f == nil {
		return nil
	}
	err := d.f.Close()
	d.f = nil
	return err
}

func (d *dayFile) ensureLocked(now time.Time) error {
	day := now.Format("2006-01-02")
	if d.f != nil && day == d.day {
		return nil
	}
	if d.f != nil {
		_ = d.f.Close()
		d.f = nil
	}
	name := filepath.Join(d.dir, fmt.Sprintf("%s-%s.jsonl", d.prefix, day))
	f, err := os.OpenFile(name, os.O_CREATE|os.O_APPEND|os.O_WRONLY, 0o644)
	if err != nil {
		return fmt.Errorf("open %s: %w", name, err)
	}
	d.f = f
	d.day = day
	return nil
}
