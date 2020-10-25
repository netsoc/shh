package server

import (
	"errors"
	"fmt"
	"regexp"
	"time"

	"github.com/gliderlabs/ssh"
	log "github.com/sirupsen/logrus"

	iam "github.com/netsoc/iam/client"
	"github.com/netsoc/shh/pkg/util"
)

var regexDirectLogin = regexp.MustCompile(`^(\S+)-ws$`)

func (s *Server) doLogin(ctx ssh.Context, password string, key ssh.PublicKey) error {
	username := ctx.User()
	m := regexDirectLogin.FindStringSubmatch(username)
	if len(m) > 0 {
		username = m[1]
		ctx.SetValue(keyWsLogin, true)
	} else {
		ctx.SetValue(keyWsLogin, false)
	}

	if key == nil {
		r, _, err := s.iam.UsersApi.Login(ctx, username, iam.LoginRequest{Password: password})
		if err != nil {
			return util.APIError(err)
		}
		ctx.SetValue(keyUserToken, r.Token)
	}

	ctx.SetValue(iam.ContextAccessToken, s.config.IAM.Token)
	u, _, err := s.iam.UsersApi.GetUser(ctx, username)
	if err != nil {
		return fmt.Errorf("failed to get info for user: %w", util.APIError(err))
	}
	ctx.SetValue(keyUser, &u)

	if key != nil {
		userKey, _, _, _, err := ssh.ParseAuthorizedKey([]byte(u.SshKey))
		if err != nil {
			return fmt.Errorf("failed to parse public key: %w", err)
		}
		if !ssh.KeysEqual(userKey, key) {
			return errors.New("user key didn't match")
		}

		if u.Renewed.Add(s.config.IAM.LoginValidity).Before(time.Now()) {
			return errors.New("user is not renewed, refusing to issue temporary token")
		}
		r, _, err := s.iam.UsersApi.IssueToken(ctx, username, iam.IssueTokenRequest{Duration: "24h"})
		if err != nil {
			return fmt.Errorf("failed to issue temporary user token: %w", err)
		}

		ctx.SetValue(keyUserToken, r.Token)
	}

	return nil
}

func (s *Server) handlePassword(ctx ssh.Context, password string) bool {
	if err := s.doLogin(ctx, password, nil); err != nil {
		log.WithError(err).WithField("user", ctx.User()).Error("User failed to authenticate")
		return false
	}

	return true
}
func (s *Server) handlePublicKey(ctx ssh.Context, key ssh.PublicKey) bool {
	if err := s.doLogin(ctx, "", key); err != nil {
		log.WithError(err).WithField("user", ctx.User()).Error("User failed to authenticate with public key")
		return false
	}

	return true
}
