package internal_test

import (
	"context"
	"fmt"
	"github.com/MicahParks/keyfunc/v3"
	. "github.com/anderslauri/open-iap/internal"
	"github.com/anderslauri/open-iap/internal/cache"
	log "github.com/sirupsen/logrus"
	"net/http"
	"os"
	"testing"
	"time"
)

func TestMain(m *testing.M) {
	lvl, _ := log.ParseLevel("DEBUG")
	log.SetLevel(lvl)
	os.Exit(m.Run())
}

// newAuthServiceListener generates a new auth service listener with dynamic port.
func newAuthServiceListener(ctx context.Context) (*AuthServiceListener, error) {
	credentials, err := googleCredentials()
	if err != nil {
		log.WithField("error", err).Fatal("Couldn't create Google IAM-credentials.")
		return nil, err
	}
	log.Info("Creating Google Workspace client.")
	gwsClient, err := NewGoogleWorkspaceClient(ctx, credentials)
	if err != nil {
		log.WithField("error", err).Fatal("Couldn't create Google Workspace client.")
		return nil, err
	}
	iamClient, err := NewIdentityAccessManagementClient(ctx, gwsClient, credentials, 5*time.Minute)
	if err != nil {
		log.WithField("error", err).Fatal("Couldn't create Google Cloud IAM-policy client.")
		return nil, err
	}
	log.Info("Creating Google Cloud token service.")
	tokenService, err := NewGoogleTokenService(ctx,
		cache.NewExpiryCache[keyfunc.Keyfunc](ctx, 1*time.Minute),
		1*time.Minute, 1*time.Minute)
	if err != nil {
		log.WithField("error", err).Fatal("Couldn't create Google Cloud token service.")
		return nil, err
	}
	log.Info("Creating Google Cloud authenticator service.")
	authenticator, err := NewGoogleCloudTokenAuthenticator(tokenService,
		cache.NewExpiryCache[UserID](ctx, 1*time.Minute), iamClient, gwsClient)
	if err != nil {
		log.WithField("error", err).Fatal("Couldn't create Google Cloud authenticator service.")
		return nil, err
	}
	listener, err := NewAuthServiceListener(ctx, "0.0.0.0", "X-Original-URL", 0, authenticator)
	if err != nil {
		return nil, err
	}
	go listener.ListenAndServe(ctx)
	// Wait until port is registered.
	for listener.Port() == 0 {
		time.Sleep(10 * time.Millisecond)
	}
	return listener, nil
}

// requestUrl compose a url for listener tests.
func requestUrl(port int, path string) string {
	return fmt.Sprintf("http://127.0.0.1:%d/%s", port, path)
}

var httpClient = &http.Client{}

func TestHealthEndpoint(t *testing.T) {
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	listener, err := newAuthServiceListener(ctx)
	if err != nil {
		t.Fatalf("Unexpected error returned, error: %s.", err)
	}
	defer listener.Close(ctx)

	req, _ := http.NewRequestWithContext(ctx, "GET", requestUrl(listener.Port(), "healthz"), nil)
	rsp, err := httpClient.Do(req)
	if err != nil {
		t.Fatalf("Unexpected error returned, error: %s.", err)
	} else if rsp.StatusCode != http.StatusOK {
		t.Fatalf("Expected status code 200 OK, status code %d was returned.", rsp.StatusCode)
	}
}

func TestAuthWithValidIdentityToken(t *testing.T) {
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	listener, err := newAuthServiceListener(ctx)
	if err != nil {
		t.Fatalf("Unexpected error returned, error: %s.", err)
	}
	defer listener.Close(ctx)

	idToken, err := requestUserGoogleIdToken(ctx, "https://myurl.com")
	if err != nil {
		t.Fatalf("Unexpected error returned, error: %s.", err)
	}
	req, _ := http.NewRequestWithContext(ctx, "GET", requestUrl(listener.Port(), "auth"), nil)
	req.Header.Set("Proxy-Authorization", fmt.Sprintf("Bearer %s", idToken))
	req.Header.Set("X-Original-URL", "https://myurl.com/hello")

	if rsp, err := httpClient.Do(req); err != nil {
		t.Fatalf("Unexpected error returned, error: %s.", err)
	} else if rsp.StatusCode != http.StatusOK {
		t.Fatalf("Expected status code 200 OK, status code %d was returned.", rsp.StatusCode)
	}
}

func TestAuthWithSelfSignedToken(t *testing.T) {
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	listener, err := newAuthServiceListener(ctx)
	if err != nil {
		t.Fatalf("Unexpected error returned, error: %s.", err)
	}
	defer listener.Close(ctx)

	idToken, err := requestGoogleSelfSignedToken(ctx, "https://myurl.com")
	if err != nil {
		t.Fatalf("Unexpected error returned, error: %s.", err)
	}
	req, _ := http.NewRequestWithContext(ctx, "GET", requestUrl(listener.Port(), "auth"), nil)
	req.Header.Set("Proxy-Authorization", fmt.Sprintf("Bearer %s", idToken))
	req.Header.Set("X-Original-URL", "https://myurl.com/hello")

	if rsp, err := httpClient.Do(req); err != nil {
		t.Fatalf("Unexpected error returned, error: %s.", err)
	} else if rsp.StatusCode != http.StatusOK {
		t.Fatalf("Expected status code 200 OK, status code %d was returned.", rsp.StatusCode)
	}
}

func BenchmarkAuthService(b *testing.B) {
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	listener, err := newAuthServiceListener(ctx)
	if err != nil {
		b.Fatalf("Unexpected error returned, error: %s.", err)
	}
	defer listener.Close(ctx)

	idToken, err := requestUserGoogleIdToken(ctx, "https://myurl.com")
	if err != nil {
		b.Fatalf("Unexpected error returned, error: %s.", err)
	}
	req, _ := http.NewRequestWithContext(ctx, "GET", requestUrl(listener.Port(), "auth"), nil)
	req.Header.Set("Proxy-Authorization", fmt.Sprintf("Bearer: %s", idToken))
	req.Header.Set("X-Original-URL", "https://myurl.com/hello")

	b.Run("BenchmarkAuthService", func(b *testing.B) {
		b.ResetTimer()
		for i := 0; i < b.N; i++ {
			_, _ = httpClient.Do(req)
		}
	})
}
