package server

import (
	"fmt"
	"io/ioutil"
	"reflect"
	"strings"

	"github.com/mitchellh/mapstructure"
	log "github.com/sirupsen/logrus"
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

// ConfigDecoderOptions enables necessary mapstructure decode hook functions
func ConfigDecoderOptions(config *mapstructure.DecoderConfig) {
	config.ErrorUnused = true
	config.DecodeHook = mapstructure.ComposeDecodeHookFunc(
		config.DecodeHook,
		stringToLogLevelHookFunc(),
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

	ListenAddress string `mapstructure:"listen_address"`
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

	return nil
}
