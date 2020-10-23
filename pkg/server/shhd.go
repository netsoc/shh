package server

import (
	"context"
	"time"

	"github.com/gliderlabs/ssh"
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
			Addr: c.ListenAddress,
		},
	}

	s.ssh.Handle(s.handleSession)

	return s
}

// Start starts the shhd server
func (s *Server) Start() error {
	return s.ssh.ListenAndServe()
}

// Stop shuts down the shhd server
func (s *Server) Stop() error {
	ctx, cancel := context.WithTimeout(context.Background(), 2*time.Second)
	defer cancel()

	return s.ssh.Shutdown(ctx)
}

func (s *Server) handleSession(sess ssh.Session) {
	sess.Write([]byte(string("Hello, world!\n")))
	sess.Close()
}
