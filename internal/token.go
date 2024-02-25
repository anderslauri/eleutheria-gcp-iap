package internal

import (
	"context"
	"errors"
	"fmt"
	"github.com/MicahParks/keyfunc/v3"
	"github.com/anderslauri/open-iap/internal/cache"
	"github.com/golang-jwt/jwt/v5"
	log "github.com/sirupsen/logrus"
	"io"
	"net/http"
	"sync/atomic"
	"time"
)

const (
	publicGoogleCerts       = "https://www.googleapis.com/oauth2/v3/certs"
	selfSignedCertsPrefix   = "https://www.googleapis.com/service_accounts/v1/jwk/"
	publicGoogleCertsIssuer = "https://accounts.google.com"
)

// GoogleTokenService is a backend representation to manage authn/authz of Google Tokens.
type GoogleTokenService struct {
	jwkClient http.Client
	jwkCache  cache.Cache[string, cache.ExpiryCacheValue[keyfunc.Keyfunc]]
	// publicKey is issuer accounts.google.com, only self-signed in cache.
	publicKey atomic.Pointer[keyfunc.Keyfunc]
}

// GoogleTokenClaims extends standard JWT claims with claim email.
type GoogleTokenClaims struct {
	Email string `json:"email"`
	jwt.RegisteredClaims
}

// TokenVerifier is a generic interface as implemented by Google Token.
type TokenVerifier[V any] interface {
	Verify(ctx context.Context, tokenString, aud string, token V) error
}

var (
	// ErrUnknownTokenType is given when token type is not identifiable.
	ErrUnknownTokenType = errors.New("unknown token type")
	// ErrMissingJWK is given when no JWK can be found in cache or retrieved.
	ErrMissingJWK = errors.New("missing jwk")
)

// NewGoogleTokenService creates a new token service for Google Tokens.
func NewGoogleTokenService(ctx context.Context, jwkCache cache.Cache[string, cache.ExpiryCacheValue[keyfunc.Keyfunc]], refreshCertsInterval time.Duration) (*GoogleTokenService, error) {
	googleTokenService := &GoogleTokenService{
		jwkCache: jwkCache,
	}
	// Load initial public certificates before starting.
	err := googleTokenService.googleCertsRefresher(ctx, refreshCertsInterval)
	if err != nil {
		return nil, err
	}
	return googleTokenService, nil
}

// readGoogleCerts is used when requesting JWK from Google Cloud.
func (t *GoogleTokenService) readGoogleCerts(ctx context.Context, url string, writer io.Writer) error {
	req, err := http.NewRequestWithContext(ctx, "GET", url, nil)
	if err != nil {
		return err
	}
	rsp, err := t.jwkClient.Do(req)
	if err != nil {
		return err
	}
	defer rsp.Body.Close()

	if _, err = io.Copy(writer, rsp.Body); err != nil {
		return err
	}
	return nil
}

// googleCertsRefresher starts a background routine to fetch JWK every 10 minutes,
// this is only for public certificates. For self-signed, this is done on demand.
func (t *GoogleTokenService) googleCertsRefresher(ctx context.Context, interval time.Duration) error {
	log.Info("Loading public certificates from Google.")
	buffer := getBuffer()
	defer putBuffer(buffer)

	if err := t.readGoogleCerts(ctx, publicGoogleCerts, buffer); err != nil {
		return err
	}

	keySet, err := keyfunc.NewJWKSetJSON(buffer.Bytes())
	if err != nil {
		return err
	}
	log.Info("Public certificates successfully loaded. Persisting in cache.")
	t.publicKey.Store(&keySet)
	// Listener to ensure public certificates are kept fresh.
	go func() {
		log.Infof("Background routine started, ensuring fresh certificates. Interval is %s.", interval.String())
		// Routine for keeping public certs synchronized.
		ticker := time.NewTicker(interval)
		defer ticker.Stop()
		for {
			select {
			case <-ctx.Done():
				return
			case <-ticker.C:
				buffer = getBuffer()
				if err := t.readGoogleCerts(ctx, publicGoogleCerts, buffer); err == nil {
					if keySet, err := keyfunc.NewJWKSetJSON(buffer.Bytes()); err == nil {
						t.publicKey.Store(&keySet)
					}
				}
				putBuffer(buffer)
			}
		}
	}()
	return nil
}

// keyFunc retrieves JWK from Google API or local cache. Mostly cache.
func (t *GoogleTokenService) keyFunc(ctx context.Context, issuer string) (keyfunc.Keyfunc, error) {
	if issuer == publicGoogleCertsIssuer {
		return *t.publicKey.Load(), nil
	}
	buf := getBuffer()
	defer putBuffer(buf)

	// Only for self-signed tokens.
	keySet, ok := t.jwkCache.Get(issuer)
	if ok {
		return keySet.Val, nil
	} else if err := t.readGoogleCerts(ctx, fmt.Sprintf("%s%s", selfSignedCertsPrefix, issuer), buf); err != nil {
		return nil, ErrMissingJWK
	} else if keySet.Val, err = keyfunc.NewJWKSetJSON(buf.Bytes()); err != nil {
		return nil, ErrMissingJWK
	}
	go t.jwkCache.Set(issuer,
		cache.ExpiryCacheValue[keyfunc.Keyfunc]{
			Val: keySet.Val,
			Exp: time.Now().Add(24 * time.Hour).Unix(),
		})
	return keySet.Val, nil
}

// Verify transform base64 encoded token string into a Token representation while verifying claims and audience.
func (t *GoogleTokenService) Verify(ctx context.Context, tokenString, aud string, tokenClaims *GoogleTokenClaims) error {
	// FIXME: This is a first pass merely to identify issuer. Optimize away.
	token, _, err := new(jwt.Parser).ParseUnverified(tokenString, jwt.MapClaims{})
	if err != nil {
		return err
	}
	issuer, _ := token.Claims.GetIssuer()

	keySet, err := t.keyFunc(ctx, issuer)
	if err != nil {
		return err
	}

	token, err = jwt.ParseWithClaims(tokenString, tokenClaims,
		keySet.Keyfunc, jwt.WithLeeway(10*time.Second), jwt.WithAudience(aud))
	if err != nil {
		return err
	} else if _, ok := token.Claims.(*GoogleTokenClaims); !ok || !token.Valid {
		return ErrUnknownTokenType
	}
	return nil
}
