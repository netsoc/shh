package server

import (
	"errors"
	"fmt"
	"io"
	"os"
	"os/exec"

	"github.com/creack/pty"
	"github.com/gliderlabs/ssh"
	iam "github.com/netsoc/iam/client"
	"github.com/netsoc/shh/pkg/util"
	log "github.com/sirupsen/logrus"
)

func (s *Server) doSession(sess ssh.Session) error {
	log.WithFields(log.Fields{
		"address": sess.RemoteAddr(),
	}).Info("Opened SSH session")

	cmd, err := util.NewShellJail(&s.config.Jail, &iam.User{
		Id:       123,
		Username: "bro",
	}, os.Getenv("PATH"), "")
	if err != nil {
		return fmt.Errorf("failed to create nsjail command: %w", err)
	}

	logR, logW, err := os.Pipe()
	if err != nil {
		return fmt.Errorf("failed to create log pipe: %w", err)
	}
	defer logR.Close()
	cmd.ExtraFiles = []*os.File{logW}

	// TODO: Does SSH not actually forward signals at all?
	sigChan := make(chan ssh.Signal)
	sess.Signals(sigChan)
	sigHandler := func() {
		for s := range sigChan {
			log.WithFields(log.Fields{
				"signal": s,
			}).Trace("Forwarding signal")
			cmd.Process.Signal(util.SSHSignalToOS(s))
		}
	}

	sshPTY, resizeChan, interactive := sess.Pty()
	if interactive {
		cmd.Env = append(cmd.Env, "TERM="+sshPTY.Term)

		ptmx, err := pty.StartWithSize(cmd, util.SSHToPTYSize(sshPTY.Window))
		if err != nil {
			return fmt.Errorf("failed to start command: %w", err)
		}
		defer ptmx.Close()

		go io.Copy(log.StandardLogger().Out, logR)

		go sigHandler()
		go func() {
			for resize := range resizeChan {
				pty.Setsize(ptmx, util.SSHToPTYSize(resize))
			}
		}()

		go io.Copy(ptmx, sess)
		go io.Copy(sess, ptmx)
	} else {
		return errors.New("must be interactive")
	}

	if err := cmd.Wait(); err != nil {
		var exitErr *exec.ExitError
		if errors.As(err, &exitErr) {
			sess.Exit(exitErr.ExitCode())
			return nil
		}

		return fmt.Errorf("command failed: %w", err)
	}

	return nil
}

func (s *Server) handleSession(sess ssh.Session) {
	if err := s.doSession(sess); err != nil {
		fmt.Fprintf(sess.Stderr(), "Error: %v\r\n", err)
		sess.Exit(-1)
	}
}
