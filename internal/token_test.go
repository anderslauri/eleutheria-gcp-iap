package internal_test

import (
	"context"
	"github.com/anderslauri/k8s-gws-authn/internal"
	"github.com/anderslauri/k8s-gws-authn/internal/cache"
	"golang.org/x/oauth2/google"
	"google.golang.org/api/idtoken"
	"google.golang.org/api/option"
	"testing"
)

// requestUserGoogleIdToken calls Google API for user (via ADC) and retrieves an ID-token.
func requestUserGoogleIdToken(ctx context.Context, aud string) (string, error) {
	credentials, err := google.FindDefaultCredentials(ctx)
	if err != nil {
		return "", err
	}
	tokenSource, err := idtoken.NewTokenSource(ctx, aud, option.WithCredentials(credentials))
	if err != nil {
		return "", err
	}
	serviceAccountIdToken, err := tokenSource.Token()
	if err != nil {
		return "", err
	}
	return serviceAccountIdToken.AccessToken, nil
}

func newTokenService(ctx context.Context) (*internal.GoogleTokenService, error) {
	jwkCache := cache.NewJwkCache(ctx)
	tokenService, err := internal.NewGoogleTokenService(ctx, jwkCache)
	if err != nil {
		return nil, err
	}
	return tokenService, nil
}

func TestNewGoogleTokenGeneration(t *testing.T) {
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	tokenService, _ := newTokenService(ctx)
	idToken, _ := requestUserGoogleIdToken(ctx, "https://myurl.com")
	token := &internal.GoogleToken{}

	if err := tokenService.NewGoogleToken(ctx, idToken, token); err != nil {
		t.Fatalf("Expected no error from token, error returned: %s", err)
	}
}

func BenchmarkNewGoogleTokenService(b *testing.B) {
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	token := &internal.GoogleToken{}
	tokenService, _ := newTokenService(ctx)
	idToken, _ := requestUserGoogleIdToken(ctx, "https://myurl.com")
	b.ResetTimer()

	for i := 0; i < b.N; i++ {
		_ = tokenService.NewGoogleToken(ctx, idToken, token)
	}
}
