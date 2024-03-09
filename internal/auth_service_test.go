package internal_test

import (
	"context"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/pem"
	"errors"
	"fmt"
	"github.com/MicahParks/keyfunc/v3"
	. "github.com/anderslauri/open-iap/internal"
	"github.com/anderslauri/open-iap/internal/cache"
	log "github.com/sirupsen/logrus"
	"math/big"
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

// newAuthServiceListenerWithClient generates a new auth service listener with dynamic port and respective client.
func newAuthServiceListenerWithClient(ctx context.Context, tlsMode bool) (*AuthServiceListener, *http.Client, error) {
	credentials, err := googleCredentials()
	if err != nil {
		log.WithField("error", err).Fatal("Couldn't create Google IAM-credentials.")
		return nil, nil, err
	}
	log.Info("Creating Google Workspace client.")
	gwsClient, err := NewGoogleWorkspaceClient(ctx, credentials)
	if err != nil {
		log.WithField("error", err).Fatal("Couldn't create Google Workspace client.")
		return nil, nil, err
	}
	iamClient, err := NewIdentityAccessManagementClient(ctx, gwsClient, credentials, 5*time.Minute)
	if err != nil {
		log.WithField("error", err).Fatal("Couldn't create Google Cloud IAM-policy client.")
		return nil, nil, err
	}
	log.Info("Creating Google Cloud token service.")
	tokenService, err := NewGoogleTokenService(ctx,
		cache.NewExpiryCache[keyfunc.Keyfunc](ctx, 1*time.Minute),
		1*time.Minute, 1*time.Minute)
	if err != nil {
		log.WithField("error", err).Fatal("Couldn't create Google Cloud token service.")
		return nil, nil, err
	}
	log.Info("Creating Google Cloud authenticator service.")
	authenticator, err := NewGoogleCloudTokenAuthenticator(tokenService,
		cache.NewExpiryCache[UserID](ctx, 1*time.Minute), iamClient, gwsClient)
	if err != nil {
		log.WithField("error", err).Fatal("Couldn't create Google Cloud authenticator service.")
		return nil, nil, err
	}
	listener, err := NewAuthServiceListener(ctx, "0.0.0.0", "X-Original-URL", 0, authenticator)
	if err != nil {
		return nil, nil, err
	}
	var pemCert []byte

	if !tlsMode {
		go func() {
			if err = listener.ListenAndServe(ctx); err != nil && !errors.Is(err, http.ErrServerClosed) {
				log.WithField("error", err).Fatal("HTTP-listener could not be started.")
			}
		}()
	} else {
		pKey, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
		if err != nil {
			return nil, nil, err
		}
		sn, err := rand.Int(rand.Reader, new(big.Int).Lsh(big.NewInt(1), 128))
		if err != nil {
			return nil, nil, err
		}
		template := x509.Certificate{
			SerialNumber: sn,
			Subject: pkix.Name{
				Organization: []string{"Open IAP"},
			},
			DNSNames:              []string{"localhost"},
			NotBefore:             time.Now(),
			NotAfter:              time.Now().Add(1 * time.Hour),
			KeyUsage:              x509.KeyUsageDigitalSignature,
			ExtKeyUsage:           []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth},
			BasicConstraintsValid: true,
		}
		derBytes, err := x509.CreateCertificate(rand.Reader, &template, &template, &pKey.PublicKey, pKey)
		if err != nil {
			return nil, nil, err
		}
		pemCert = pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: derBytes})
		if pemCert == nil {
			return nil, nil, errors.New("failed to encode certificate to PEM")
		}
		privBytes, err := x509.MarshalPKCS8PrivateKey(pKey)
		if err != nil {
			return nil, nil, err
		}
		pemKey := pem.EncodeToMemory(&pem.Block{Type: "PRIVATE KEY", Bytes: privBytes})
		if pemKey == nil {
			return nil, nil, errors.New("failed to encode key to PEM")
		}
		go func() {
			if err = listener.ListenAndServeWithTLS(ctx, pemKey, pemCert); err != nil && !errors.Is(err, http.ErrServerClosed) {
				log.WithField("error", err).Fatal("HTTPS-listener could not be started.")
			}
		}()
	}
	// Wait until port is registered.
	for listener.Port() == 0 {
		time.Sleep(10 * time.Millisecond)
	}
	client := &http.Client{}

	if tlsMode {
		certPool := x509.NewCertPool()
		_ = certPool.AppendCertsFromPEM(pemCert)
		client = &http.Client{
			Transport: &http.Transport{
				TLSClientConfig: &tls.Config{
					RootCAs: certPool,
				},
			},
		}
	}
	return listener, client, nil
}

// requestUrl compose a url for listener tests.
func requestUrl(port int, path string, tls bool) string {
	protocol := "http://"
	if tls {
		protocol = "https://"
	}
	return fmt.Sprintf("%slocalhost:%d/%s", protocol, port, path)
}

func TestHealth(t *testing.T) {
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	listener, _, err := newAuthServiceListenerWithClient(ctx, false)
	if err != nil {
		t.Fatalf("Unexpected error returned, error: %s.", err)
	}
	defer listener.Close(ctx)
	httpClient := &http.Client{}

	req, _ := http.NewRequestWithContext(ctx, "GET", requestUrl(listener.Port(), "healthz", false), nil)
	rsp, err := httpClient.Do(req)
	if err != nil {
		t.Fatalf("Unexpected error returned, error: %s.", err)
	} else if rsp.StatusCode != http.StatusOK {
		t.Fatalf("Expected status code 200 OK, status code %d was returned.", rsp.StatusCode)
	}
}

func BenchmarkAuthService(b *testing.B) {
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	plainTextListener, httpClient, _ := newAuthServiceListenerWithClient(ctx, false)
	defer plainTextListener.Close(ctx)
	tlsListener, httpsClient, _ := newAuthServiceListenerWithClient(ctx, true)
	defer tlsListener.Close(ctx)
	idToken, _ := requestGoogleServiceAccountIdToken(ctx, "https://myurl.com")

	plainTextReq, _ := http.NewRequestWithContext(ctx, "GET", requestUrl(plainTextListener.Port(), "auth", false), nil)
	plainTextReq.Header.Set("Proxy-Authorization", fmt.Sprintf("bearer %s", idToken))
	plainTextReq.Header.Set("X-Original-URL", "https://myurl.com/hello")

	tlsReq, _ := http.NewRequestWithContext(ctx, "GET", requestUrl(tlsListener.Port(), "auth", true), nil)
	tlsReq.Header.Set("Proxy-Authorization", fmt.Sprintf("bearer %s", idToken))
	tlsReq.Header.Set("X-Original-URL", "https://myurl.com/hello")

	b.Run("BenchmarkAuthServiceWithoutTLS", func(b *testing.B) {
		b.ResetTimer()
		for i := 0; i < b.N; i++ {
			_, _ = httpClient.Do(plainTextReq)
		}
	})
	b.Run("BenchmarkAuthServiceWithTLS", func(b *testing.B) {
		b.ResetTimer()
		for i := 0; i < b.N; i++ {
			_, _ = httpsClient.Do(tlsReq)
		}
	})
}

func TestGoogleCloudTokenAuthentication(t *testing.T) {
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	plainTextAuthService, httpClient, err := newAuthServiceListenerWithClient(ctx, false)
	if err != nil {
		t.Fatalf("Unexpected error returned, error: %s.", err)
	}
	defer plainTextAuthService.Close(ctx)

	tlsAuthService, httpsClient, err := newAuthServiceListenerWithClient(ctx, true)
	if err != nil {
		t.Fatalf("Unexpected error returned, error: %s.", err)
	}
	defer tlsAuthService.Close(ctx)

	var tests = []struct {
		name       string
		tls        bool
		error      error
		selfSigned bool
		audience   string
		requestUrl string
	}{
		{"TestAuthServiceWithValidIdentityTokenWithTLS", true,
			nil, false, "https://myurl.com", "https://myurl.com/hello"},
		{"TestAuthServiceWithValidIdentityTokenWithoutTLS", false,
			nil, false, "https://myurl.com", "https://myurl.com/hello"},
		{"TestAuthServiceWithValidSelfSignedTokenWithoutTLS", false,
			nil, true, "https://myurl.com", "https://myurl.com/hello"},
		{"TestAuthServiceWithValidSelfSignedTokenWithTLS", true,
			nil, true, "https://myurl.com", "https://myurl.com/hello"},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			var (
				port  int
				token string
				err   error
				rsp   *http.Response
			)

			if !tt.selfSigned {
				token, err = requestGoogleServiceAccountSelfSignedIdToken(ctx, tt.audience)
			} else {
				token, err = requestGoogleServiceAccountIdToken(ctx, tt.audience)
			}
			if err != nil {
				t.Fatalf("Unexpected error returned, error: %s.", err)
			} else if tt.tls {
				port = tlsAuthService.Port()
			} else {
				port = plainTextAuthService.Port()
			}
			req, _ := http.NewRequestWithContext(ctx, "GET", requestUrl(port, "auth", tt.tls), nil)
			req.Header.Set("Proxy-Authorization", fmt.Sprintf("bearer %s", token))
			req.Header.Set("X-Original-URL", tt.requestUrl)

			if tt.tls {
				rsp, err = httpsClient.Do(req)
			} else {
				rsp, err = httpClient.Do(req)
			}

			if err != nil && tt.error == nil {
				t.Fatalf("Unexpected error returned, error: %s.", err)
			} else if rsp.StatusCode != http.StatusOK {
				t.Fatalf("Expected status code 200 OK, status code %d was returned.", rsp.StatusCode)
			}
		})
	}
}
