package server

import (
	"fmt"
	"regexp"

	"github.com/gliderlabs/ssh"
	log "github.com/sirupsen/logrus"

	iam "github.com/netsoc/iam/client"
	"github.com/netsoc/shh/pkg/util"
)

var regexDirectLogin = regexp.MustCompile(`^(\S+)-ws$`)

func (s *Server) doLogin(ctx ssh.Context, password string) error {
	username := ctx.User()
	m := regexDirectLogin.FindStringSubmatch(username)
	if len(m) > 0 {
		username = m[1]
		ctx.SetValue(keyWsLogin, true)
	} else {
		ctx.SetValue(keyWsLogin, false)
	}

	r, _, err := s.iam.UsersApi.Login(ctx, username, iam.LoginRequest{Password: password})
	if err != nil {
		return util.APIError(err)
	}
	ctx.SetValue(keyUserToken, r.Token)

	ctx.SetValue(iam.ContextAccessToken, s.config.IAM.Token)
	u, _, err := s.iam.UsersApi.GetUser(ctx, username)
	if err != nil {
		return fmt.Errorf("failed to get info for user %v: %w", username, util.APIError(err))
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
