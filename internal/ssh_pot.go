package internal

import (
	"context"
	"fmt"
	"io"
	"log"
	"time"

	"krain-sec/internal/decoy"
	"krain-sec/internal/store"

	"github.com/gliderlabs/ssh"
	"github.com/golang/glog"
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
		glog.Infof("ssh auth attempt host=%s ip=%s user=%s password=%s success=%v",
			HostFQDN, ip, user, password, ok)
		store.RecordAuthAttempt("ssh", ip, user, password, ok)
		return ok
	})

	s := &ssh.Server{
		Addr:    ":22",
		Version: SSHVersion,
		MaxTimeout: 30 * time.Minute,
		IdleTimeout: 10 * time.Minute,
		Handler: ssh.Handler(func(sess ssh.Session) {
			if !sem.tryAcquire() {
				glog.Warningf("ssh session limit ip=%v", sess.RemoteAddr())
				fmt.Fprintln(sess, "Maximum number of sessions exceeded. Try again later.")
				return
			}
			defer sem.release()

			remote := ""
			if addr := sess.RemoteAddr(); addr != nil {
				remote = addr.String()
			}
			user := sess.User()
			glog.Infof("ssh session open host=%s ip=%s user=%s", HostFQDN, remote, user)

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
		glog.Info("shutting down ssh server")
		if err := s.Shutdown(shutdownCtx); err != nil {
			glog.Info("ssh shutdown err: ", err)
		}
	}()
	log.Printf("Starting SSH server on :22 as %s...\n", HostFQDN)

	if err := s.ListenAndServe(); err != nil {
		return err
	}
	return nil
}
