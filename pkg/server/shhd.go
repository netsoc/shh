package server

import (
	"context"
	"crypto/tls"
	"errors"
	"fmt"
	"net/http"
	"time"

	"github.com/gliderlabs/ssh"
	iam "github.com/netsoc/iam/client"
	"github.com/netsoc/shh/pkg/util"
)

type key int

const (
	keyUser = iota
	keyUserToken
)

// Server represents the shhd server
type Server struct {
	config Config

	iam *iam.APIClient
	ssh *ssh.Server
}

// NewServer creates a new shhd server
func NewServer(c Config) *Server {
	cfg := iam.NewConfiguration()
	cfg.BasePath = c.IAM.URL
	if c.IAM.AllowInsecure {
		cfg.HTTPClient = &http.Client{
			Transport: &http.Transport{
				TLSClientConfig: &tls.Config{
					InsecureSkipVerify: true,
				},
			},
		}
	}

	s := &Server{
		config: c,

		iam: iam.NewAPIClient(cfg),
		ssh: &ssh.Server{
			Addr:        c.SSH.ListenAddress,
			HostSigners: c.SSH.HostKeys,
		},
	}

	s.ssh.Handle(s.handleSession)
	s.ssh.PasswordHandler = s.handlePassword

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
