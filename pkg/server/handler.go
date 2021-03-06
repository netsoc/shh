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

func (s *Server) shellSession(sess ssh.Session) error {
	command := sess.RawCommand()
	sshPTY, resizeChan, interactive := sess.Pty()
	if sess.Context().Value(keyWsLogin).(bool) {
		if interactive {
			command = "netsoc webspace login"
		} else {
			command = "netsoc webspace exec -- " + command
		}
	}

	user := sess.Context().Value(keyUser).(*iam.User)
	token := sess.Context().Value(keyUserToken).(string)
	cmd, err := util.NewShellJail(&s.config.Jail, user, token, os.Getenv("PATH"), command)
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

	if interactive {
		cmd.Env = append(cmd.Env, "TERM="+sshPTY.Term)

		ptmx, err := pty.StartWithSize(cmd, util.SSHToPTYSize(sshPTY.Window))
		if err != nil {
			return fmt.Errorf("failed to start interactive command: %w", err)
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
		stdin, err := cmd.StdinPipe()
		if err != nil {
			return fmt.Errorf("failed to create stdin pipe: %w", err)
		}
		stdout, err := cmd.StdoutPipe()
		if err != nil {
			return fmt.Errorf("failed to create stdout pipe: %w", err)
		}
		stderr, err := cmd.StderrPipe()
		if err != nil {
			return fmt.Errorf("failed to create stderr pipe: %w", err)
		}

		if err := cmd.Start(); err != nil {
			return fmt.Errorf("failed to start command: %w", err)
		}

		go io.Copy(log.StandardLogger().Out, logR)

		go sigHandler()

		go io.Copy(stdin, sess)
		go io.Copy(sess, stdout)
		go io.Copy(sess.Stderr(), stderr)
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
func (s *Server) doSession(sess ssh.Session) error {
	user := sess.Context().Value(keyUser).(*iam.User)
	log.WithFields(log.Fields{
		"user":    user.Username,
		"address": sess.RemoteAddr(),
		"command": sess.RawCommand(),
	}).Info("Opened SSH session")

	// TODO: maybe if the user is doing a login skip allocating a jail and executing the CLI?
	return s.shellSession(sess)
}

func (s *Server) handleSession(sess ssh.Session) {
	if err := s.doSession(sess); err != nil {
		fmt.Fprintf(sess.Stderr(), "Error: %v\r\n", err)
		sess.Exit(-1)
	}
}
