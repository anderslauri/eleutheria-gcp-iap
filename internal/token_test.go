package internal_test

import (
	"context"
	"encoding/json"
	"fmt"
	"github.com/MicahParks/keyfunc/v3"
	"github.com/anderslauri/open-iap/internal"
	"github.com/anderslauri/open-iap/internal/cache"
	"golang.org/x/oauth2/google"
	"google.golang.org/api/iamcredentials/v1"
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

// requestGoogleSelfSignedToken creates a self-signed JWT.
func requestGoogleSelfSignedToken(ctx context.Context, aud string) (string, error) {
	credentials, err := google.FindDefaultCredentialsWithParams(ctx,
		google.CredentialsParams{
			Scopes: []string{"https://www.googleapis.com/auth/cloud-platform"},
		})
	if err != nil {
		return "", err
	}
	claims := make(map[string]any)
	_ = json.Unmarshal(credentials.JSON, &claims)
	email, _ := claims["client_email"].(string)
	token, _ := credentials.TokenSource.Token()
	iat := time.Now().Unix()
	exp := time.Now().Add(2 * time.Hour).Unix()
	pServiceAccountService, err := iamcredentials.NewService(ctx, option.WithCredentials(credentials))
	if err != nil {
		return "", err
	}
	signedJwtRequest := pServiceAccountService.Projects.ServiceAccounts.SignJwt(
		fmt.Sprintf("projects/-/serviceAccounts/%s", email),
		&iamcredentials.SignJwtRequest{
			Payload: fmt.Sprintf(
				"{\"iss\":\"%s\", \"aud\":\"%s\",\"sub\":\"%s\", \"iat\":%d, \"exp\":%d}",
				email, aud, email, iat, exp),
		})

	signedJwtRequest.Header().Set("Authorization", fmt.Sprintf("Bearer %s", token.AccessToken))
	signedJwtResponse, err := signedJwtRequest.Context(ctx).Do()
	if err != nil {
		return "", err
	}
	return signedJwtResponse.SignedJwt, nil
}

func newTokenService(ctx context.Context) (*internal.GoogleTokenService, error) {
	defaultInterval := 5 * time.Minute
	jwkCache := cache.NewExpiryCache[keyfunc.Keyfunc](ctx, defaultInterval)
	tokenService, err := internal.NewGoogleTokenService(ctx, jwkCache, defaultInterval, 1*time.Minute)
	if err != nil {
		return nil, err
	}
	return tokenService, nil
}

func TestGoogleServiceAccountIdTokenVerification(t *testing.T) {
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

func TestGoogleSelfSignedTokenVerification(t *testing.T) {
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	aud := "https://myurl.com"
	tokenService, _ := newTokenService(ctx)
	selfSigned, err := requestGoogleSelfSignedToken(ctx, aud)
	if err != nil {
		t.Fatal(err)
	}
	token := &internal.GoogleTokenClaims{}

	if err := tokenService.Verify(ctx, selfSigned, aud, token); err != nil {
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
