package internal

import (
	"context"
	"fmt"
	"io"
	"log"
	"time"

	"krain-sec/internal/decoy"

	"github.com/gliderlabs/ssh"
	"github.com/golang/glog"
)

func StartSSHServer(ctx context.Context) error {
	passwordAuth := ssh.PasswordAuth(func(sshCtx ssh.Context, password string) bool {
		glog.Infof("ssh auth attempt host=%s ip=%s user=%s password=%s",
			HostFQDN, sshCtx.RemoteAddr().String(), sshCtx.User(), password)
		return sshCtx.User() == "admin" && password == "secret123"
	})

	s := &ssh.Server{
		Addr:    ":2222",
		Version: SSHVersion,
		Handler: ssh.Handler(func(sess ssh.Session) {
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
			time.Sleep(800 * time.Millisecond)
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
	log.Printf("Starting SSH server on :2222 as %s...\n", HostFQDN)

	if err := s.ListenAndServe(); err != nil {
		return err
	}
	return nil
}
