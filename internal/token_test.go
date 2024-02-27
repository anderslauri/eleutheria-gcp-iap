package internal_test

import (
	"context"
	"github.com/MicahParks/keyfunc/v3"
	"github.com/anderslauri/open-iap/internal"
	"github.com/anderslauri/open-iap/internal/cache"
	"golang.org/x/oauth2/google"
	"google.golang.org/api/idtoken"
	"google.golang.org/api/option"
	"testing"
	"time"
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
	defaultInterval := 5 * time.Minute
	jwkCache := cache.NewExpiryCache[keyfunc.Keyfunc](ctx, defaultInterval)
	tokenService, err := internal.NewGoogleTokenService(ctx, jwkCache, defaultInterval)
	if err != nil {
		return nil, err
	}
	return tokenService, nil
}

func TestNewGoogleTokenGeneration(t *testing.T) {
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	aud := "https://myurl.com"
	tokenService, _ := newTokenService(ctx)
	idToken, _ := requestUserGoogleIdToken(ctx, aud)
	token := &internal.GoogleTokenClaims{}

	if err := tokenService.Verify(ctx, idToken, aud, token); err != nil {
		t.Fatalf("Expected no error from token, error returned: %s", err)
	}
}

func BenchmarkNewGoogleTokenService(b *testing.B) {
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	aud := "https://myurl.com"
	token := &internal.GoogleTokenClaims{}
	tokenService, _ := newTokenService(ctx)
	idToken, _ := requestUserGoogleIdToken(ctx, aud)
	b.ResetTimer()

	for i := 0; i < b.N; i++ {
		_ = tokenService.Verify(ctx, idToken, aud, token)
	}
}
