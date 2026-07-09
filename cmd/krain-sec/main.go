package main

import (
	"context"
	"fmt"
	"net"
	"net/http"
	"os"
	"os/signal"
	"syscall"
	"time"

	"github.com/golang/glog"
)

type HTTPClient struct {
	ip string
	id int
}

var HTTPClientList []HTTPClient

func main() {
	ctx, cancel := signal.NotifyContext(context.Background(), os.Interrupt, syscall.SIGTERM)
	defer cancel()

	go func() {
		if err := startHTTPServer(ctx); err != nil && err != http.ErrServerClosed {
			glog.Info("HTTP SERVER ERROR: ", err)
			os.Exit(1)
		}
	}()

	<-ctx.Done()
	glog.Info("SHUTTING DOWN GRACEFULLY")
}

func startHTTPServer(ctx context.Context) error {
	mux := http.NewServeMux()
	mux.HandleFunc("/", landingPage)
	s := &http.Server{
		Addr:         ":8080",
		Handler:      mux,
		ReadTimeout:  10 * time.Second,
		WriteTimeout: 10 * time.Second,
		IdleTimeout:  10 * time.Second,
	}

	go func() {
		<-ctx.Done()
		glog.Info("shutting down http server")

		shutdownCtx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
		defer cancel()

		if err := s.Shutdown(shutdownCtx); err != nil {
			glog.Info("http shuttdonw err: ", err)
		}
	}()
	glog.Info("http server on 8080")
	return s.ListenAndServe()
}

func extractIP(r *http.Request) string {
	ip, _, err := net.SplitHostPort(r.RemoteAddr)
	if err != nil {
		return r.RemoteAddr
	}
	return ip
}

func landingPage(w http.ResponseWriter, r *http.Request) {
	w.Header().Set("Content-Type", "text/plain; charset=utf-8")
	w.WriteHeader(http.StatusOK)
	w.Write([]byte("Hello, World"))
}

type Middleware func(http.HandlerFunc) http.HandlerFunc

func withMiddleware(handler http.HandlerFunc, middlewares ...Middleware) http.HandlerFunc {
	for i := len(middlewares) - 1; i >= 0; i-- {
		handler = middlewares[i](handler)
	}
	return handler
}

func logIPMiddleware(next http.HandlerFunc) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		ip := extractIP(r)

		HTTPClientList = append(HTTPClientList, HTTPClient{
			ip: ip,
			id: len(HTTPClientList) + 1,
		})

		fmt.Sprint("[HTTP] - %s %s\n", ip, r.URL.Path)
		next(w, r)
	}
}
