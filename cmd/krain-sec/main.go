package main

import (
	"context"
	"log/slog"
	"net/http"
	"os"
	"os/signal"
	"path/filepath"
	"syscall"

	"krain-sec/internal"
	"krain-sec/internal/logging"
	"krain-sec/internal/store"

	"github.com/gliderlabs/ssh"
)

func main() {
	os.Exit(run())
}

func run() int {
	logDir := os.Getenv("LOG_DIR")
	if logDir == "" {
		logDir = "logs"
	}
	_ = os.MkdirAll(logDir, 0o755)
	if abs, err := filepath.Abs(logDir); err == nil {
		logDir = abs
	}
	_ = os.Setenv("LOG_DIR", logDir)

	if err := logging.Init(logDir); err != nil {
		slog.Error("logging init failed", "err", err)
		return 1
	}
	defer logging.Close()

	if err := store.InitFromEnv(); err != nil {
		slog.Error("event store init failed", "err", err)
		return 1
	}
	defer store.Close()

	ctx, cancel := signal.NotifyContext(context.Background(), os.Interrupt, syscall.SIGTERM)
	defer cancel()
	store.StartRetention(ctx)

	slog.Info("startup",
		"log_dir", logDir,
		"retention_days", envOr("LOG_RETENTION_DAYS", "7"),
		"log_level", envOr("LOG_LEVEL", "info"),
		"app_log", logging.Path(),
	)

	exitCode := 0
	go func() {
		if err := internal.StartHTTPServer(ctx); err != nil && err != http.ErrServerClosed {
			slog.Error("http server failed", "err", err)
			exitCode = 1
			cancel()
		}
	}()
	go func() {
		if err := internal.StartSSHServer(ctx); err != nil && err != ssh.ErrServerClosed {
			slog.Warn("ssh decoy unavailable", "err", err)
		}
	}()
	go func() {
		if err := internal.StartMySQLDecoy(ctx); err != nil {
			slog.Warn("mysql decoy unavailable", "err", err)
		}
	}()
	go func() {
		if err := internal.StartGrafanaDecoy(ctx); err != nil {
			slog.Warn("grafana decoy unavailable", "err", err)
		}
	}()

	<-ctx.Done()
	slog.Info("shutdown")
	return exitCode
}

func envOr(k, def string) string {
	if v := os.Getenv(k); v != "" {
		return v
	}
	return def
}
