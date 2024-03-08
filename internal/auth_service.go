package internal

import (
	"context"
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
	port          atomic.Value
	host          string
	authenticator Authenticator
}

// ProxyServiceListener is an implementation of reverse proxy to use authenticator, either HTTP(S) and/or CONNECT.
type ProxyServiceListener struct {
	serviceListener
}

// Listener is an interface for a listener implementation.
type Listener interface {
	Close(ctx context.Context) error
	Port() int
	Open(ctx context.Context) error
}

// NewAuthServiceListener creates a new HTTP(s)-server for /auth. Open(ctx context.Context) must be invoked to server HTTP.
func NewAuthServiceListener(_ context.Context, host, xForwardedUrlHeader string, port uint16, auth Authenticator) (*AuthServiceListener, error) {
	a := &AuthServiceListener{
		serviceListener: serviceListener{
			httpServer:    &http.Server{},
			listener:      nil,
			host:          host,
			authenticator: auth,
		},
		xForwardedUrlHeader: xForwardedUrlHeader,
	}
	a.port.Store(int(port))

	mux := http.NewServeMux()
	mux.HandleFunc("GET /healthz", a.healthz)
	mux.HandleFunc("GET /auth", a.auth)
	a.httpServer.Handler = mux
	log.Info("Listener is successfully configured.")
	return a, nil
}

// Port returns port of running listener.
func (a *AuthServiceListener) Port() int {
	return a.port.Load().(int)
}

// Open listener to incoming requests. Blocking.
func (a *AuthServiceListener) Open(_ context.Context) error {
	port := a.port.Load().(int)

	if l, err := net.Listen("tcp", fmt.Sprintf("%s:%d", a.host, port)); err != nil {
		log.WithField("error", err).Fatal("TCP-listener could not be started.")
	} else {
		a.listener = l
		a.port.Store(l.Addr().(*net.TCPAddr).Port)
	}
	return a.httpServer.Serve(a.listener)
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
