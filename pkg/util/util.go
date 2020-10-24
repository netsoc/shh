package util

import (
	"errors"
	"fmt"
	"os"
	"syscall"

	"github.com/creack/pty"
	"github.com/gliderlabs/ssh"
	iam "github.com/netsoc/iam/client"
)

// SSHToPTYSize converts an SSH window size to pty window size
func SSHToPTYSize(s ssh.Window) *pty.Winsize {
	return &pty.Winsize{
		Cols: uint16(s.Width),
		Rows: uint16(s.Height),
	}
}

// SSHSignalToOS converts an SSH signal to an os.Signal
func SSHSignalToOS(s ssh.Signal) os.Signal {
	switch s {
	case ssh.SIGABRT:
		return syscall.SIGABRT
	case ssh.SIGALRM:
		return syscall.SIGALRM
	case ssh.SIGFPE:
		return syscall.SIGFPE
	case ssh.SIGHUP:
		return syscall.SIGHUP
	case ssh.SIGILL:
		return syscall.SIGILL
	case ssh.SIGINT:
		return syscall.SIGINT
	case ssh.SIGKILL:
		return syscall.SIGKILL
	case ssh.SIGPIPE:
		return syscall.SIGPIPE
	case ssh.SIGQUIT:
		return syscall.SIGQUIT
	case ssh.SIGSEGV:
		return syscall.SIGSEGV
	case ssh.SIGTERM:
		return syscall.SIGTERM
	case ssh.SIGUSR1:
		return syscall.SIGUSR1
	case ssh.SIGUSR2:
		return syscall.SIGUSR2
	}

	return syscall.SIGTERM
}

// EnsureNod makes sure a filesystem node exists
func EnsureNod(path string, mode uint32, dev uint64) error {
	_, err := os.Stat(path)
	if err == nil {
		return nil
	}
	if !os.IsNotExist(err) {
		return fmt.Errorf("error stat'ing %v: %w", path, err)
	}

	return syscall.Mknod(path, mode, int(dev))
}

// APIError re-formats an OpenAPI-generated API client error
func APIError(err error) error {
	var iamGeneric iam.GenericOpenAPIError
	if ok := errors.As(err, &iamGeneric); ok {
		if iamError, ok := iamGeneric.Model().(iam.Error); ok {
			return errors.New(iamError.Message)
		}
		return err
	}

	return err
}
