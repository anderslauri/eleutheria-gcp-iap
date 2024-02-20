package internal_test

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"github.com/anderslauri/k8s-gws-authn/internal"
	"golang.org/x/oauth2/google"
	"io"
	"net/http"
	"net/url"
	"testing"
)

// GoogleCloudCredentialsOAuthConfig used to retrieve ID-tokens for normal user account.
type GoogleCloudCredentialsOAuthConfig struct {
	ClientID     string `json:"client_id"`
	ClientSecret string `json:"client_secret"`
	RefreshToken string `json:"refresh_token"`
	GrantType    string `json:"grant_type"`
}

// GoogleCloudTokenResponse is the response struct from Google API when requesting ID-token,
// other fields are included also but we only care about the id-token from this response.
type GoogleCloudTokenResponse struct {
	IdToken string `json:"id_token"`
}

// requestUserGoogleIdToken calls Google API for existing local user (via ADC) and retrieves an ID-token,
// only used for verifying token generation function. Audience can only be set by using a Google Service Account.
func requestUserGoogleIdToken(ctx context.Context) (string, error) {
	credentials, err := google.FindDefaultCredentials(ctx)
	if err != nil {
		return "", err
	}
	clientConfig := &GoogleCloudCredentialsOAuthConfig{
		GrantType: "refresh_token",
	}

	_ = json.Unmarshal(credentials.JSON, &clientConfig)
	clientRequestBody, _ := json.Marshal(clientConfig)

	rURL, _ := url.Parse("https://oauth2.googleapis.com/token")
	httpReq := &http.Request{URL: rURL, Method: "POST", Body: io.NopCloser(bytes.NewReader(clientRequestBody))}

	rsp, err := httpClient.Do(httpReq)
	if err != nil {
		return "", err
	} else if rsp.StatusCode != http.StatusOK {
		return "", errors.New("non expected return status code from googleapis")
	}
	defer rsp.Body.Close()
	body, _ := io.ReadAll(rsp.Body)
	googleResponseBody := &GoogleCloudTokenResponse{}
	_ = json.Unmarshal(body, &googleResponseBody)
	return googleResponseBody.IdToken, nil
}

func newTokenService(ctx context.Context) (*internal.GoogleTokenService, error) {
	jwkCache := internal.NewJwkCache(ctx)
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
	idToken, _ := requestUserGoogleIdToken(ctx)
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
	idToken, _ := requestUserGoogleIdToken(ctx)
	b.ResetTimer()

	for i := 0; i < b.N; i++ {
		_ = tokenService.NewGoogleToken(ctx, idToken, token)
	}
}
