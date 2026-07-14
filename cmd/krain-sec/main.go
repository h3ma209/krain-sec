package main

import (
	"context"
	"flag"
	"net/http"
	"os"
	"os/signal"
	"path/filepath"
	"syscall"

	"krain-sec/internal"
	"krain-sec/internal/store"

	"github.com/gliderlabs/ssh"
	"github.com/golang/glog"
)

func main() {
	logDir := os.Getenv("LOG_DIR")
	if logDir == "" {
		logDir = "logs"
	}
	_ = os.MkdirAll(logDir, 0o755)
	abs, err := filepath.Abs(logDir)
	if err == nil {
		logDir = abs
	}
	_ = os.Setenv("LOG_DIR", logDir)

	_ = flag.Set("logtostderr", "false")
	_ = flag.Set("alsologtostderr", "true")
	_ = flag.Set("log_dir", logDir)
	flag.Parse()
	defer glog.Flush()

	if err := store.InitFromEnv(); err != nil {
		glog.Errorf("file store init failed: %v", err)
		os.Exit(1)
	}
	defer store.Close()

	ctx, cancel := signal.NotifyContext(context.Background(), os.Interrupt, syscall.SIGTERM)
	defer cancel()
	store.StartRetention(ctx)
	glog.Infof("logging to %s (daily JSONL + glog, retain 7d)", logDir)

	go func() {
		if err := internal.StartHTTPServer(ctx); err != nil && err != http.ErrServerClosed {
			glog.Info("HTTP SERVER ERROR: ", err)
			os.Exit(1)
		}
	}()
	go func() {
		if err := internal.StartSSHServer(ctx); err != nil && err != ssh.ErrServerClosed {
			glog.Info("SSH SERVER ERROR: ", err)
			os.Exit(1)
		}
	}()
	go func() {
		if err := internal.StartMySQLDecoy(ctx); err != nil {
			glog.Info("MYSQL DECOY ERROR: ", err)
			os.Exit(1)
		}
	}()
	go func() {
		if err := internal.StartGrafanaDecoy(ctx); err != nil {
			glog.Info("GRAFANA DECOY ERROR: ", err)
			os.Exit(1)
		}
	}()

	<-ctx.Done()
	glog.Info("SHUTTING DOWN GRACEFULLY")
}
