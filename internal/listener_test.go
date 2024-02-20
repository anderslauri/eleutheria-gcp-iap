package internal_test

import (
	"context"
	"fmt"
	. "github.com/anderslauri/k8s-gws-authn/internal"
	log "github.com/sirupsen/logrus"
	"net/http"
	"os"
	"testing"
)

func TestMain(m *testing.M) {
	lvl, _ := log.ParseLevel("DEBUG")
	log.SetLevel(lvl)
	os.Exit(m.Run())
}

// localServiceListener generates a new listener per dynamic port.
func localServiceListener(ctx context.Context) (Listener, error) {
	listener, err := NewListener(ctx, "0.0.0.0", "X-Original-URI", "X-Scheme", 0)
	if err != nil {
		return nil, err
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
	listener, err := localServiceListener(ctx)
	if err != nil {
		t.Fatalf("Unexpected error returned, error: %s.", err)
	}
	defer listener.Shutdown(ctx)

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
	listener, err := localServiceListener(ctx)
	if err != nil {
		t.Fatalf("Unexpected error returned, error: %s.", err)
	}
	defer listener.Shutdown(ctx)

	idToken, err := requestUserGoogleIdToken(ctx)
	if err != nil {
		t.Log(err)
	}
	req, _ := http.NewRequestWithContext(ctx, "GET", requestUrl(listener.Port(), "auth"), nil)
	req.Header.Set("X-Forwarded-Proxy-Authorization", fmt.Sprintf("Bearer: %s", idToken))

	rsp, err := httpClient.Do(req)
	if err != nil {
		t.Fatalf("Unexpected error returned, error: %s.", err)
	} else if rsp.StatusCode != http.StatusOK {
		t.Fatalf("Expected status code 200 OK, status code %d was returned.", rsp.StatusCode)
	}
}
