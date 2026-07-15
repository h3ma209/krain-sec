package internal

import (
	"context"
	"fmt"
	"io"
	"log/slog"
	"time"

	"krain-sec/internal/decoy"
	"krain-sec/internal/store"

	"github.com/gliderlabs/ssh"
)

func StartSSHServer(ctx context.Context) error {
	sem := sshSessionSem()

	passwordAuth := ssh.PasswordAuth(func(sshCtx ssh.Context, password string) bool {
		ip := ""
		if addr := sshCtx.RemoteAddr(); addr != nil {
			ip = addr.String()
		}
		user := sshCtx.User()
		ok := user == "admin" && password == "secret123"
		// password only in auth JSONL (store), not operational log
		slog.Info("ssh auth", "host", HostFQDN, "ip", ip, "user", user, "success", ok)
		store.RecordAuthAttempt("ssh", ip, user, password, ok)
		return ok
	})

	s := &ssh.Server{
		Addr:        ":22",
		Version:     SSHVersion,
		MaxTimeout:  30 * time.Minute,
		IdleTimeout: 10 * time.Minute,
		Handler: ssh.Handler(func(sess ssh.Session) {
			if !sem.tryAcquire() {
				slog.Warn("ssh session limit", "ip", fmt.Sprint(sess.RemoteAddr()))
				fmt.Fprintln(sess, "Maximum number of sessions exceeded. Try again later.")
				return
			}
			defer sem.release()

			remote := ""
			if addr := sess.RemoteAddr(); addr != nil {
				remote = addr.String()
			}
			user := sess.User()
			slog.Info("ssh session", "host", HostFQDN, "ip", remote, "user", user)

			motd := fmt.Sprintf(
				"***************************************************************************\n"+
					"*  Authorized use only. All activity on %s is monitored.  *\n"+
					"***************************************************************************\n"+
					"Last login: %s from %s\n",
				HostFQDN,
				time.Now().UTC().Format("Mon Jan 2 15:04:05 MST 2006"),
				remote,
			)
			time.Sleep(400 * time.Millisecond)
			io.WriteString(sess, motd)
			decoy.RunShell(sess, sess, user, HostShort, HostFQDN, remote)
		}),
	}
	if err := s.SetOption(passwordAuth); err != nil {
		return fmt.Errorf("failed to set ssh option: %w", err)
	}

	go func() {
		<-ctx.Done()
		shutdownCtx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
		defer cancel()
		slog.Info("ssh shutting down")
		if err := s.Shutdown(shutdownCtx); err != nil {
			slog.Error("ssh shutdown failed", "err", err)
		}
	}()
	slog.Info("ssh listen", "addr", ":22", "host", HostFQDN)

	if err := s.ListenAndServe(); err != nil {
		return err
	}
	return nil
}
