package server

import (
	"fmt"

	"github.com/gliderlabs/ssh"
	iam "github.com/netsoc/iam/client"
	"github.com/netsoc/shh/pkg/util"
	log "github.com/sirupsen/logrus"
)

func (s *Server) doLogin(ctx ssh.Context, password string) error {
	r, _, err := s.iam.UsersApi.Login(ctx, ctx.User(), iam.LoginRequest{Password: password})
	if err != nil {
		return util.APIError(err)
	}
	ctx.SetValue(keyUserToken, r.Token)

	ctx.SetValue(iam.ContextAccessToken, s.config.IAM.Token)
	u, _, err := s.iam.UsersApi.GetUser(ctx, ctx.User())
	if err != nil {
		return fmt.Errorf("failed to get info for user %v: %w", ctx.User(), util.APIError(err))
	}
	ctx.SetValue(keyUser, &u)

	return nil
}
func (s *Server) handlePassword(ctx ssh.Context, password string) bool {
	if err := s.doLogin(ctx, password); err != nil {
		log.WithError(err).WithField("user", ctx.User()).Error("User failed to authenticate")
		return false
	}

	return true
}
