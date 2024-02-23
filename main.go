package main

import (
	"context"
	config "github.com/anderslauri/open-iap/gen"
	"github.com/anderslauri/open-iap/internal"
	log "github.com/sirupsen/logrus"
	"net/http"
	"os"
	"os/signal"
)

func main() {
	log.SetFormatter(&log.JSONFormatter{})

	appConfigFile := "app_config.pkl"
	if customConfigFile := os.Getenv("APPLICATION_CONFIG_FILE"); len(customConfigFile) > 0 {
		appConfigFile = os.Getenv("APPLICATION_CONFIG_FILE")
	}
	ctx, cancel := context.WithCancel(context.Background())

	cfg, err := config.LoadFromPath(ctx, appConfigFile)
	if err != nil {
		log.WithField("error", err).Fatal("Failed to load application configuration.")
	}
	lvl, _ := log.ParseLevel(cfg.Logger.LogLevel.String())
	log.SetLevel(lvl)
	log.SetReportCaller(cfg.Logger.ReportCaller)

	log.Info("Application configuration successfully loaded. Starting new listener.")
	// Really need to find a better solution for parameter passing.
	listener, err := internal.NewListener(ctx, cfg.Host, cfg.HeaderMapping.Url,
		cfg.Port, cfg.PublicGoogleCerts.RefreshInterval.GoDuration(), cfg.JwkCache.Cleaner.GoDuration(),
		cfg.JwtCache.Cleaner.GoDuration(), cfg.GooglePolicyBindings.RefreshInterval.GoDuration())
	if err != nil {
		log.WithField("error", err).Fatalf("Not possible to start listener.")
	}
	go func() {
		if err = listener.Open(ctx); err != nil && err != http.ErrServerClosed {
			log.WithField("error", err).Fatal("Failed to start listener.")
		}
	}()
	defer func() {
		log.Info("Exiting application.")
		_ = listener.Close(ctx)
		// In memory only, no reason to wait.
		cancel()
	}()
	// Wait for signal.
	sigs := make(chan os.Signal, 1)
	signal.Notify(sigs, os.Interrupt)
	<-sigs
}
