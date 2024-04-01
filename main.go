package main

import (
	"context"
	"errors"
	"github.com/MicahParks/keyfunc/v3"
	config "github.com/anderslauri/open-iap/gen"
	"github.com/anderslauri/open-iap/internal"
	"github.com/anderslauri/open-iap/internal/cache"
	log "github.com/sirupsen/logrus"
	"golang.org/x/oauth2/google"
	admin "google.golang.org/api/admin/directory/v1"
	"google.golang.org/api/iamcredentials/v1"
	"net/http"
	"net/url"
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
	log.Info("Loading Google IAM-credentials using ADC.")
	credentials, err := google.FindDefaultCredentials(ctx,
		admin.AdminDirectoryGroupReadonlyScope,
		iamcredentials.CloudPlatformScope,
	)
	if err != nil {
		log.WithField("error", err).Fatal("Couldn't create Google IAM-credentials.")
	}
	log.Info("Creating Google Workspace client.")
	gwsClient, err := internal.NewGoogleWorkspaceClient(ctx, credentials)
	if err != nil {
		log.WithField("error", err).Fatal("Couldn't create Google Workspace client.")
	}
	log.Info("Creating Identity Access Management client.")
	iamClient, err := internal.NewIdentityAccessManagementClient(ctx, gwsClient,
		credentials, cfg.IamPolicy.RefreshInterval.GoDuration())
	if err != nil {
		log.WithField("error", err).Fatal("Couldn't create Google Cloud IAM-policy client.")
	}
	log.Info("Creating Google Cloud token service.")

	tokenService, err := internal.NewGoogleTokenService(ctx,
		cache.NewExpiryCache[keyfunc.Keyfunc](ctx, cfg.JwkCache.Cleaner.GoDuration()),
		cfg.GoogleCerts.RefreshInterval.GoDuration(), cfg.Leeway.GoDuration())
	if err != nil {
		log.WithField("error", err).Fatal("Couldn't create Google Cloud token service.")
	}
	log.Info("Creating Google Cloud authenticator service.")

	excludedHosts := make([]url.URL, 0, len(cfg.ExcludedHosts))
	for _, host := range cfg.ExcludedHosts {
		excludedHost, err := url.Parse(host)
		if err != nil {
			log.WithField("error", err).Fatalf("Couldn't parse excluded host url %s.", host)
		}
		excludedHosts = append(excludedHosts, *excludedHost)
	}

	authenticator, err := internal.NewGoogleCloudTokenAuthenticator(tokenService,
		cache.NewExpiryCache[internal.GoogleServiceAccount](ctx, cfg.JwtCache.Cleaner.GoDuration()),
		iamClient, gwsClient, excludedHosts)
	if err != nil {
		log.WithField("error", err).Fatal("Couldn't create Google Cloud authenticator service.")
	}
	log.Info("Application configuration successfully loaded. Starting new authentication service listener..")
	authService, err := internal.NewAuthServiceListener(ctx, cfg.Host, cfg.HeaderMapping.Url, cfg.Port, authenticator)
	if err != nil {
		log.WithField("error", err).Fatalf("Not possible to start listener.")
	}

	if cfg.Tls != nil && len(cfg.Tls.CertFile) > 0 && len(cfg.Tls.KeyFile) > 0 {
		log.Info("Starting TLS-listener.")
		pKey, err := os.ReadFile(cfg.Tls.KeyFile)
		if err != nil {
			log.WithField("error", err).Fatalf("Not possible to read private key file.")
		}
		cert, err := os.ReadFile(cfg.Tls.CertFile)
		if err != nil {
			log.WithField("error", err).Fatal("Not possible to read certificate key file.")
		}
		go func() {
			if err = authService.ListenAndServeWithTLS(ctx, pKey, cert); err != nil && !errors.Is(http.ErrServerClosed, err) {
				log.WithField("error", err).Fatal("Failed to start TLS-listener.")
			}
		}()
	} else {
		go func() {
			if err = authService.ListenAndServe(ctx); err != nil && !errors.Is(http.ErrServerClosed, err) {
				log.WithField("error", err).Fatal("Failed to start listener.")
			}
		}()
	}
	defer func() {
		log.Info("Exiting application.")
		_ = authService.Close(ctx)
		// In memory only, no reason to wait.
		cancel()
	}()
	// Wait for signal.
	sigs := make(chan os.Signal, 1)
	signal.Notify(sigs, os.Interrupt)
	<-sigs
}
