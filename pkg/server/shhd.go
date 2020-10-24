package server

import (
	"context"
	"errors"
	"fmt"
	"time"

	"github.com/gliderlabs/ssh"
	"github.com/netsoc/shh/pkg/util"
)

// Server represents the shhd server
type Server struct {
	config Config

	ssh *ssh.Server
}

// NewServer creates a new shhd server
func NewServer(c Config) *Server {
	s := &Server{
		config: c,
		ssh: &ssh.Server{
			Addr:        c.SSH.ListenAddress,
			HostSigners: c.SSH.HostKeys,
		},
	}

	s.ssh.Handle(s.handleSession)

	return s
}

// Start starts the shhd server
func (s *Server) Start() error {
	if err := util.InitJail(&s.config.Jail); err != nil {
		return fmt.Errorf("failed to initialize shell jail: %w", err)
	}

	if err := s.ssh.ListenAndServe(); err != nil && !errors.Is(err, ssh.ErrServerClosed) {
		return err
	}

	return nil
}

// Stop shuts down the shhd server
func (s *Server) Stop() error {
	ctx, cancel := context.WithTimeout(context.Background(), 2*time.Second)
	defer cancel()

	return s.ssh.Shutdown(ctx)
}
