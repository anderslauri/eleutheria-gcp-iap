package internal

import (
	"context"
	"fmt"
	log "github.com/sirupsen/logrus"
	"net"
	"net/http"
	"strings"
)

type listener struct {
	service       *http.Server
	port          int
	xHeaderURI    string
	xHeaderScheme string
	tokenService  *GoogleTokenService
}

const (
	proxyAuthorizationHeader = "X-Forwarded-Proxy-Authorization"
	authorizationHeader      = "X-Forwarded-Authorization"
)

// NewListener creates a new HTTP-server. Non-blocking invocation, panic if not started correctly.
func NewListener(ctx context.Context, host, xURI, xScheme string, port uint16) (Listener, error) {
	googleTokenService, err := NewGoogleTokenService(ctx, NewJwkCache(ctx))
	if err != nil {
		return nil, err
	}

	tcpListener, err := net.Listen("tcp", fmt.Sprintf("%s:%d", host, port))
	if err != nil {
		return nil, err
	}

	l := &listener{
		service:       &http.Server{},
		xHeaderURI:    xURI,
		xHeaderScheme: xScheme,
		tokenService:  googleTokenService,
		port:          tcpListener.Addr().(*net.TCPAddr).Port,
	}
	mux := http.NewServeMux()
	mux.HandleFunc("/healthz", l.healthz)
	mux.HandleFunc("/auth", l.auth)
	l.service.Handler = mux

	go func() {
		log.Info("Starting background listener for requests.")
		if err := l.service.Serve(tcpListener); err != http.ErrServerClosed {
			log.WithField("error", err).Fatal("Unable to start ListenAndServe.")
		}
	}()
	return l, nil
}

// Port returns port of running listener.
func (l *listener) Port() int {
	return l.port
}

// Shutdown listener. Invocation is blocking.
func (l *listener) Shutdown(ctx context.Context) error {
	return l.service.Shutdown(ctx)
}

func (l *listener) healthz(w http.ResponseWriter, r *http.Request) {
	if r.Method != "GET" {
		w.WriteHeader(http.StatusBadRequest)
		return
	}
	w.WriteHeader(http.StatusOK)
}

func (l *listener) auth(w http.ResponseWriter, r *http.Request) {
	if r.Method != "GET" {
		w.WriteHeader(http.StatusBadRequest)
		return
	}
	tokenString := r.Header.Get(authorizationHeader)
	if xProxyAuthorization := r.Header.Get(proxyAuthorizationHeader); len(xProxyAuthorization) > 0 {
		tokenString = xProxyAuthorization
	} else if len(tokenString) == 0 {
		log.Debug("Request missing JWT.")
		w.WriteHeader(http.StatusProxyAuthRequired)
		return
	}
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	token := getGoogleToken()
	defer putGoogleToken(token)
	// Bearer: is removed as prefix.
	jwt := strings.TrimSpace(tokenString[7:])

	if err := l.tokenService.NewGoogleToken(ctx, jwt, token); err != nil {
		log.WithField("error", err).Debug("Failed generating Google Token.")
		w.WriteHeader(http.StatusProxyAuthRequired)
		return
	}
	log.Debugf("Processing successful request with email: %s and audience %s.", token.email, token.aud)
}
