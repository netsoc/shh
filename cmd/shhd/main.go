package main

import (
	"encoding/json"
	"net"
	"os"
	"os/signal"
	"strings"
	"time"

	"github.com/MakeNowJust/heredoc"
	"github.com/fsnotify/fsnotify"
	"github.com/gliderlabs/ssh"
	log "github.com/sirupsen/logrus"
	"github.com/spf13/pflag"
	"github.com/spf13/viper"
	"golang.org/x/sys/unix"

	"github.com/netsoc/shh/pkg/server"
)

var srv *server.Server

func init() {
	// Config defaults
	viper.SetDefault("log_level", log.InfoLevel)

	viper.SetDefault("iam.url", "https://iam.netsoc.ie/v1")
	viper.SetDefault("iam.token", "")
	viper.SetDefault("iam.token_file", "")
	viper.SetDefault("iam.allow_insecure", false)
	viper.SetDefault("iam.login_validity", 365*24*time.Hour)

	viper.SetDefault("ssh.listen_address", ":22")
	viper.SetDefault("ssh.host_keys", []ssh.Signer{})
	viper.SetDefault("ssh.host_key_files", []string{})

	viper.SetDefault("jail.tmp_dir", "/tmp/shh")
	viper.SetDefault("jail.log_level", "WARNING")
	viper.SetDefault("jail.uid_start", 100000)
	viper.SetDefault("jail.gid_start", 100000)
	viper.SetDefault("jail.cgroups.name", "shh")
	viper.SetDefault("jail.cgroups.memory", 128*1024*1024)
	viper.SetDefault("jail.cgroups.pids", 64)
	viper.SetDefault("jail.cgroups.cpu_time", 200)
	viper.SetDefault("jail.home_size", 32*1024*1024)
	viper.SetDefault("jail.greeting", heredoc.Doc(`
		Welcome to Netsoc SHH (not a typo :P).
		The latest version of the CLI is pre-installed (type netsoc).

		For more information, see https://docs.netsoc.ie.
	`))

	viper.SetDefault("jail.cli_extra", map[string]interface{}{
		"last_update_check": "9999-12-31T23:59:59Z",
	})

	viper.SetDefault("jail.network.interface", "")
	ip, net, err := net.ParseCIDR("192.168.0.1/16")
	if err != nil {
		panic(err)
	}
	net.IP = ip
	viper.SetDefault("jail.network.address", net)

	// Config file loading
	viper.SetConfigType("yaml")
	viper.SetConfigName("shhd")
	viper.AddConfigPath("/run/config")
	viper.AddConfigPath(".")

	// Config from environment
	viper.SetEnvPrefix("shhd")
	viper.SetEnvKeyReplacer(strings.NewReplacer(".", "_"))
	viper.AutomaticEnv()

	// Config from flags
	pflag.StringP("log_level", "l", "info", "log level")
	pflag.Parse()
	if err := viper.BindPFlags(pflag.CommandLine); err != nil {
		log.WithError(err).Fatal("Failed to bind pflags to config")
	}

	if err := viper.ReadInConfig(); err != nil {
		log.WithError(err).Warn("Failed to read config")
	}
}

func reload() {
	if srv != nil {
		stop()
		srv = nil
	}

	var config server.Config
	if err := viper.Unmarshal(&config, server.ConfigDecoderOptions); err != nil {
		log.WithField("err", err).Fatal("Failed to parse configuration")
	}

	if err := config.ReadSecrets(); err != nil {
		log.WithError(err).Fatal("Failed to read config secrets from files")
	}

	log.SetLevel(config.LogLevel)
	cJSON, err := json.Marshal(config)
	if err != nil {
		log.WithError(err).Fatal("Failed to encode config as JSON")
	}
	log.WithField("config", string(cJSON)).Debug("Got config")

	srv = server.NewServer(config)

	log.Info("Starting server")
	go func() {
		if err := srv.Start(); err != nil {
			log.WithError(err).Fatal("Failed to start server")
		}
	}()
}

func stop() {
	if err := srv.Stop(); err != nil {
		log.WithError(err).Fatal("Failed to stop iamd server")
	}
}

func main() {
	sigs := make(chan os.Signal)
	signal.Notify(sigs, unix.SIGINT, unix.SIGTERM)

	viper.OnConfigChange(func(e fsnotify.Event) {
		log.WithField("file", e.Name).Info("Config changed, reloading")
		reload()
	})
	viper.WatchConfig()
	reload()

	<-sigs
	stop()
}
