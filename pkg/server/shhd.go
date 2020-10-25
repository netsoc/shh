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
	keyWsLogin
)

// Server represents the shhd server
type Server struct {
	config Config

	iam *iam.APIClient
	ssh *ssh.Server
}

// NewServer creates a new shhd server
func NewServer(c Config) *Server {
	insecureClient := &http.Client{
		Transport: &http.Transport{
			TLSClientConfig: &tls.Config{
				InsecureSkipVerify: true,
			},
		},
	}

	iamCfg := iam.NewConfiguration()
	iamCfg.BasePath = c.IAM.URL
	if c.IAM.AllowInsecure {
		iamCfg.HTTPClient = insecureClient
	}

	s := &Server{
		config: c,

		iam: iam.NewAPIClient(iamCfg),
		ssh: &ssh.Server{
			Addr:        c.SSH.ListenAddress,
			HostSigners: c.SSH.HostKeys,
		},
	}

	s.ssh.Handle(s.handleSession)
	s.ssh.PasswordHandler = s.handlePassword
	s.ssh.PublicKeyHandler = s.handlePublicKey

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
