package main

import (
	"context"
	"github.com/anderslauri/k8s-gws-authn/internal"
	config "github.com/anderslauri/k8s-gws-authn/pkl/gen"
	log "github.com/sirupsen/logrus"
	"os"
	"time"
)

const (
	defaultConfigFile     = "DefaultConfig.pkl"
	envVariableConfigFile = "GWS_AUTH_CONFIG_FILE"
)

func main() {
	log.SetFormatter(&log.JSONFormatter{})
	log.SetReportCaller(true)

	configFile := defaultConfigFile
	if customConfig := os.Getenv(envVariableConfigFile); len(customConfig) > 0 {
		configFile = os.Getenv(envVariableConfigFile)
	}
	ctx, cancel := context.WithCancel(context.Background())
	defer func() {
		cancel()
		// Allow operations to complete.
		time.Sleep(5 * time.Second)
		log.Info("Application exiting.")
	}()

	cfg, err := loadApplicationConfig(ctx, configFile)
	if err != nil {
		log.WithField("error", err).Fatalf("Failed to load application configuration.")
	} else {
		log.Infof("Configuring new log level to %s.", cfg.LogLevel.String())
		lvl, _ := log.ParseLevel(cfg.LogLevel.String())
		log.SetLevel(lvl)
	}
	log.Info("Application configuration successfully loaded.")

	listener, err := internal.NewListener(ctx, cfg.Host, cfg.HeaderMapping.Scheme, cfg.HeaderMapping.Uri, cfg.Port)
	if err != nil {
		log.WithField("error", err).Fatalf("Not possible to start listener.")
	}
	defer listener.Shutdown(ctx)
	// Waiting for signal to halt application.
	sigs := make(chan os.Signal, 1)
	<-sigs
}

func loadApplicationConfig(ctx context.Context, filePath string) (*config.ApplicationConfig, error) {
	c, err := config.LoadFromPath(ctx, filePath)
	if err != nil {
		return c, err
	}
	return c, err
}
