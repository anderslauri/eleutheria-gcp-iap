package internal

import (
	"context"
	"crypto/tls"
	"fmt"
	"github.com/golang-jwt/jwt/v5/request"
	log "github.com/sirupsen/logrus"
	"net"
	"net/http"
	"net/url"
	"strings"
	"sync/atomic"
)

// AuthServiceListener is an implementation use authenticator on /auth-path.
type AuthServiceListener struct {
	serviceListener
	xForwardedUrlHeader string
}

type serviceListener struct {
	httpServer    *http.Server
	listener      net.Listener
	port          atomic.Uint32
	host          string
	authenticator Authenticator
}

// ProxyServiceListener is an implementation of reverse proxy to use authenticator, either HTTP(S) and/or CONNECT.
type ProxyServiceListener struct {
	serviceListener
}

// Listener is an interface for a listener implementation.
type Listener interface {
	Shutdown(ctx context.Context) error
	Port() int
	ListenAndServe(ctx context.Context) error
	ListenAndServeWithTLS(ctx context.Context, key, cert []byte)
}

func newAuthServiceListener(_ context.Context, host, xForwardedUrlHeader string, port uint16, auth Authenticator) (*AuthServiceListener, error) {
	a := &AuthServiceListener{
		serviceListener: serviceListener{
			httpServer:    &http.Server{},
			listener:      nil,
			host:          host,
			authenticator: auth,
		},
		xForwardedUrlHeader: xForwardedUrlHeader,
	}
	a.port.Store(uint32(port))

	mux := http.NewServeMux()
	mux.HandleFunc("GET /healthz", a.healthz)
	mux.HandleFunc("GET /auth", a.auth)
	a.httpServer.Handler = mux
	log.Info("Listener is successfully configured.")
	return a, nil
}

// NewAuthServiceListener creates a new HTTP-server for /auth-endpoint. Open(ctx context.Context) must be invoked to listen.
func NewAuthServiceListener(ctx context.Context, host, xForwardedUrlHeader string, port uint16, auth Authenticator) (*AuthServiceListener, error) {
	return newAuthServiceListener(ctx, host, xForwardedUrlHeader, port, auth)
}

// Port returns port of running listener.
func (a *AuthServiceListener) Port() int {
	return int(a.port.Load())
}

// ListenAndServe listener for incoming requests. Blocking.
func (a *AuthServiceListener) ListenAndServe(_ context.Context) error {
	port := a.port.Load()

	if l, err := net.Listen("tcp", fmt.Sprintf("%s:%d", a.host, port)); err != nil {
		return err
	} else {
		a.listener = l
		a.port.Store(uint32(l.Addr().(*net.TCPAddr).Port))
	}
	return a.httpServer.Serve(a.listener)
}

func (a *AuthServiceListener) ListenAndServeWithTLS(_ context.Context, key, cert []byte) error {
	port := a.port.Load()

	if l, err := net.Listen("tcp", fmt.Sprintf("%s:%d", a.host, port)); err != nil {
		return err
	} else {
		a.listener = l
		a.port.Store(uint32(l.Addr().(*net.TCPAddr).Port))
	}
	certificate, err := tls.X509KeyPair(cert, key)
	if err != nil {
		return err
	}
	config := &tls.Config{
		MinVersion: tls.VersionTLS13,
	}
	config.NextProtos = append(config.NextProtos, "http/1.1")
	config.Certificates = make([]tls.Certificate, 1)
	config.Certificates[0] = certificate
	listener := tls.NewListener(a.listener, config)
	return a.httpServer.Serve(listener)
}

// Close listener. Blocking.
func (a *AuthServiceListener) Close(ctx context.Context) error {
	return a.httpServer.Shutdown(ctx)
}

func (a *AuthServiceListener) healthz(w http.ResponseWriter, r *http.Request) {
	w.WriteHeader(http.StatusOK)
}

func (a *AuthServiceListener) auth(w http.ResponseWriter, r *http.Request) {
	tokenString, _ := request.HeaderExtractor{"Proxy-Authorization", "Authorization"}.ExtractToken(r)
	requestURL, err := url.Parse(r.Header.Get(a.xForwardedUrlHeader))

	switch {
	case err != nil:
	case len(requestURL.String()) == 0:
	case len(tokenString) < 7:
	case !strings.EqualFold(tokenString[:7], "bearer "):
	default:
		// Re-slice string that we remove Bearer: prefix - also remove an optional blank space if present.
		tokenString = strings.TrimPrefix(tokenString[7:], " ")
		goto authenticate
	}
	log.WithField("error", err).Error("Failed to parse request url or token header value.")
	w.WriteHeader(http.StatusUnauthorized)
	return

authenticate:
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	if err := a.authenticator.Authenticate(ctx, tokenString, *requestURL); err != nil {
		w.WriteHeader(http.StatusUnauthorized)
		return
	}
}
