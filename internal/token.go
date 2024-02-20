package internal

import (
	"context"
	"errors"
	"fmt"
	"github.com/MicahParks/keyfunc/v3"
	"github.com/golang-jwt/jwt/v5"
	log "github.com/sirupsen/logrus"
	"io"
	"net/http"
	"time"
)

// TokenType is a custom type definition for types of Google tokens which are supported.
type TokenType string

const (
	googleIdToken           TokenType = "Id Token"
	googleSelfSignedToken   TokenType = "Self Signed"
	defaultLeeway                     = 30 * time.Second
	publicGoogleCerts                 = "https://www.googleapis.com/oauth2/v3/certs"
	selfSignedCertsPrefix             = "https://www.googleapis.com/service_accounts/v1/jwk/"
	publicGoogleCertsIssuer           = "https://accounts.google.com"
)

var (
	// ErrUnknownTokenType is given when no error is present, however, token type is not identifiable.
	ErrUnknownTokenType = errors.New("unknown token type")
	// ErrMissingEmailClaim is given when claim email is not present.
	ErrMissingEmailClaim = errors.New("missing email claim")
	// ErrMissingAudClaim is given when claim audience claim is not present.
	ErrMissingAudClaim = errors.New("missing aud claim")
	// ErrMissingJWK is given when no JWK can be found in cache or retrieved.
	ErrMissingJWK = errors.New("missing jwk")
)

// NewGoogleTokenService creates a new token service for Google Tokens.
func NewGoogleTokenService(ctx context.Context, jwkCache Cache) (*GoogleTokenService, error) {
	googleTokenService := &GoogleTokenService{
		jwkSet: jwkCache,
	}
	// Load initial public certificates before starting.
	err := googleTokenService.googleCertsRefresher(ctx, 10*time.Minute)
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
	// Store key set in atomic.Value. Most common scenario.
	t.publicKeyFunc.Store(keySet)
	// Background routine for cache refresh of JWK for public certs.
	log.Info("Public certificates successfully loaded. Persisting in cache.")
	t.once.Do(func() {
		log.Infof("Background routine started, ensuring fresh certificates. Interval is %s.", interval.String())
		go func() {
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
						keySet, err := keyfunc.NewJWKSetJSON(buffer.Bytes())
						if err == nil {
							t.publicKeyFunc.Store(keySet)
						}
					}
					putBuffer(buffer)
				}
			}
		}()
	})
	return nil
}

// keyFunc retrieve JWK from Google API or local cache. Mostly cache.
func (t *GoogleTokenService) keyFunc(ctx context.Context, issuer string) (keyfunc.Keyfunc, error) {
	if issuer == publicGoogleCertsIssuer {
		return t.publicKeyFunc.Load().(keyfunc.Keyfunc), nil
	}
	buf := getBuffer()
	defer putBuffer(buf)

	var (
		keySet any
		err    error
		ok     bool
	)
	// Should only be for self-signed tokens.
	keySet, ok = t.jwkSet.Get(issuer)
	if !ok {
		if err = t.readGoogleCerts(ctx,
			fmt.Sprintf("%s%s", selfSignedCertsPrefix, issuer), buf); err != nil {
			return nil, ErrMissingJWK
		} else if keySet, err = keyfunc.NewJWKSetJSON(buf.Bytes()); err != nil {
			return nil, ErrMissingJWK
		}
		// Update catch to ensure we avoid RTT to Google API.
		params := getCacheParams()
		defer putCacheParams(params)
		params.key = issuer
		params.val = buf.Bytes()
		t.jwkSet.Set(params)
		return keySet.(keyfunc.Keyfunc), nil
	}
	return keySet.(keyfunc.Keyfunc), nil
}

// NewGoogleToken transform base64 encoded token string into a GoogleToken representation,
// performs both claim assertion and verification that token is properly signed by Google.
func (t *GoogleTokenService) NewGoogleToken(ctx context.Context, tokenString string, googleToken *GoogleToken) error {
	var issuer string
	// Identify issuer of token.
	token, _, err := new(jwt.Parser).ParseUnverified(tokenString, jwt.MapClaims{})
	if err != nil {
		return err
	}
	issuer, _ = token.Claims.GetIssuer()

	tokenClaims := &GoogleTokenClaims{}
	defer putGoogleTokenClaims(tokenClaims)

	keySet, err := t.keyFunc(ctx, issuer)
	if err != nil {
		return err
	}
	// Parse token with claims. Defer with JWK signature validation
	// until we can tell if this a
	if token, err := jwt.ParseWithClaims(tokenString, tokenClaims, keySet.Keyfunc, jwt.WithLeeway(defaultLeeway)); err != nil {
		return err
	} else if claims, ok := token.Claims.(*GoogleTokenClaims); ok && token.Valid {
		// Ensure claim email and aud is present. Also set defined
		// type of token given issuer value. If self-signed, issuer
		// will be equal to claim of email (service account).
		switch {
		case len(claims.Email) == 0:
			return ErrMissingEmailClaim
		case len(claims.Audience) == 0:
			return ErrMissingAudClaim
		case claims.Email == claims.Issuer:
			googleToken.typeOf = googleSelfSignedToken
		default:
			googleToken.typeOf = googleIdToken
		}
		googleToken.exp = claims.ExpiresAt.Time
		googleToken.iat = claims.IssuedAt.Time
		googleToken.issuer = claims.Issuer
		googleToken.aud = claims.Audience[0]
		googleToken.email = claims.Email
		return nil
	}
	return ErrUnknownTokenType
}
