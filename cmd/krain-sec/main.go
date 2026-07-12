package main

import (
	"context"
	"flag"
	"net/http"
	"os"
	"os/signal"
	"syscall"

	"krain-sec/internal"

	"github.com/gliderlabs/ssh"
	"github.com/golang/glog"
)

func main() {
	_ = flag.Set("logtostderr", "true")
	flag.Parse()
	defer glog.Flush()

	ctx, cancel := signal.NotifyContext(context.Background(), os.Interrupt, syscall.SIGTERM)
	defer cancel()

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

	<-ctx.Done()
	glog.Info("SHUTTING DOWN GRACEFULLY")
}
