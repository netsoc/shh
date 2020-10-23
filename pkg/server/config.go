package server

import (
	"fmt"
	"io/ioutil"
	"reflect"
	"strings"

	"github.com/gliderlabs/ssh"
	"github.com/mitchellh/mapstructure"
	log "github.com/sirupsen/logrus"
	gossh "golang.org/x/crypto/ssh"
)

// stringToLogLevelHookFunc returns a mapstructure.DecodeHookFunc which parses a logrus Level from a string
func stringToLogLevelHookFunc() mapstructure.DecodeHookFunc {
	return func(f reflect.Type, t reflect.Type, data interface{}) (interface{}, error) {
		if f.Kind() != reflect.String || t != reflect.TypeOf(log.InfoLevel) {
			return data, nil
		}

		var level log.Level
		err := level.UnmarshalText([]byte(data.(string)))
		return level, err
	}
}

// stringToSSHSignerHookFunc returns a mapstructure.DecodeHookFunc which parses a logrus Level from a string
func stringToSSHSignerHookFunc() mapstructure.DecodeHookFunc {
	signerType := reflect.TypeOf((*ssh.Signer)(nil)).Elem()
	return func(f reflect.Type, t reflect.Type, data interface{}) (interface{}, error) {
		if f.Kind() != reflect.String || t != signerType {
			return data, nil
		}

		k, err := gossh.ParsePrivateKey([]byte(data.(string)))
		if err != nil {
			return nil, fmt.Errorf("failed to parse x509 private key: %w", err)
		}

		return k, nil
	}
}

// ConfigDecoderOptions enables necessary mapstructure decode hook functions
func ConfigDecoderOptions(config *mapstructure.DecoderConfig) {
	config.ErrorUnused = true
	config.DecodeHook = mapstructure.ComposeDecodeHookFunc(
		config.DecodeHook,
		stringToLogLevelHookFunc(),
		stringToSSHSignerHookFunc(),
	)
}

// Config represents shhd's config
type Config struct {
	LogLevel log.Level `mapstructure:"log_level"`

	IAM struct {
		URL           string
		Token         string
		TokenFile     string `mapstructure:"token_file"`
		AllowInsecure bool   `mapstructure:"allow_insecure"`
	}

	SSH struct {
		ListenAddress string `mapstructure:"listen_address"`

		HostKeys     []ssh.Signer `mapstructure:"host_keys"`
		HostKeyFiles []string     `mapstructure:"host_key_files"`
	}
}

// ReadSecrets loads values for secret config options from files
func (c *Config) ReadSecrets() error {
	if c.IAM.TokenFile != "" {
		t, err := ioutil.ReadFile(c.IAM.TokenFile)
		if err != nil {
			return fmt.Errorf("failed to read IAM token file: %w", err)
		}

		c.IAM.TokenFile = strings.TrimSpace(string(t))
	}

	for _, f := range c.SSH.HostKeyFiles {
		data, err := ioutil.ReadFile(f)
		if err != nil {
			return fmt.Errorf("failed to read SSH host key file %v: %w", f, err)
		}

		k, err := gossh.ParsePrivateKey(data)
		if err != nil {
			return fmt.Errorf("failed to parse SSH host key file %v: %w", f, err)
		}

		c.SSH.HostKeys = append(c.SSH.HostKeys, k)
	}

	return nil
}
