package internal

import (
	"context"
	"fmt"
	"io"
	"log"
	"time"

	"github.com/gliderlabs/ssh"
	"github.com/golang/glog"
)

func StartSSHServer(ctx context.Context) error {
	ssh.Handle(func(s ssh.Session) {
		io.WriteString(s, fmt.Sprintf("Welcome to the Go SSH Server, %s!\n", s.User()))
	})

	// Configure password authentication
	passwordAuth := ssh.PasswordAuth(func(ctx ssh.Context, password string) bool {
		clientIP := ctx.RemoteAddr().String()
		clientUsername := ctx.User()
		glog.Infof("client IP: %s, client username: %s", clientIP, clientUsername)
		return ctx.User() == "admin" && password == "secret123"
	})

	// Start the server with the authentication option
	s := &ssh.Server{
		Addr: ":2222",
		Handler: ssh.Handler(func(s ssh.Session) {
			clientIP := s.RemoteAddr().String()
			clientUsername := s.User()
			glog.Infof("client IP: %s, client username: %s", clientIP, clientUsername)
			time.Sleep(10 * time.Second)
			io.WriteString(s, fmt.Sprintf("Welcome to the Go SSH Server, %s!\n", s.User()))
		}),
	}
	if err := s.SetOption(passwordAuth); err != nil {
		return fmt.Errorf("failed to set ssh option: %w", err)
	}

	go func() {
		<-ctx.Done()
		shutdownCtx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
		defer cancel()
		glog.Info("shutting down ssh server")
		if err := s.Shutdown(shutdownCtx); err != nil {
			glog.Info("ssh shutdown err: ", err)
		}
	}()
	log.Println("Starting SSH server on :2222...")

	if err := s.ListenAndServe(); err != nil {
		return err
	}

	return nil
}
