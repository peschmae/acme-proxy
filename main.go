// Command acme-proxy is an ACME server for the hosts of one Internal Domain.
// It proves control with HTTP-01 on the internal network and obtains
// publicly trusted certificates from a Public CA using DNS-01.
package main

import (
	"context"
	"errors"
	"fmt"
	"log/slog"
	"net/http"
	"os"
	"os/signal"
	"path/filepath"
	"strings"
	"syscall"
	"time"

	"github.com/go-chi/chi/v5"
	"github.com/go-chi/chi/v5/middleware"

	"github.com/peschmae/acme-proxy/pkg/acme"
	"github.com/peschmae/acme-proxy/pkg/public"
)

const letsEncryptStaging = "https://acme-staging-v02.api.letsencrypt.org/directory"

func main() {
	logger := slog.New(slog.NewTextHandler(os.Stderr, nil))
	slog.SetDefault(logger)
	if err := run(logger); err != nil {
		logger.Error("acme-proxy stopped", "error", err)
		os.Exit(1)
	}
}

type env struct{ errs []error }

func (e *env) required(name string) string {
	v := strings.TrimSpace(os.Getenv(name))
	if v == "" {
		e.errs = append(e.errs, fmt.Errorf("%s must be set", name))
	}
	return v
}

func (e *env) optional(name, def string) string {
	if v := strings.TrimSpace(os.Getenv(name)); v != "" {
		return v
	}
	return def
}

func (e *env) list(name string) []string {
	var out []string
	for _, v := range strings.Split(os.Getenv(name), ",") {
		if v = strings.TrimSpace(v); v != "" {
			out = append(out, v)
		}
	}
	return out
}

func (e *env) duration(name string, def time.Duration) time.Duration {
	v := strings.TrimSpace(os.Getenv(name))
	if v == "" {
		return def
	}
	d, err := time.ParseDuration(v)
	if err != nil {
		e.errs = append(e.errs, fmt.Errorf("%s: %v", name, err))
	}
	return d
}

func run(logger *slog.Logger) error {
	e := &env{}
	internalDomain := e.required("ACME_PROXY_INTERNAL_DOMAIN")
	wildcardBases := e.list("ACME_PROXY_WILDCARD_BASES")
	listen := e.optional("ACME_PROXY_LISTEN", ":443")
	tlsCert := e.required("ACME_PROXY_TLS_CERT")
	tlsKey := e.required("ACME_PROXY_TLS_KEY")
	stateDir := e.optional("ACME_PROXY_STATE_DIR", "./data")
	challengeResolver := e.optional("ACME_PROXY_CHALLENGE_RESOLVER", "")
	orderLifetime := e.duration("ACME_PROXY_ORDER_LIFETIME", 24*time.Hour)
	challengeTimeout := e.duration("ACME_PROXY_CHALLENGE_TIMEOUT", 10*time.Second)
	publicOrderTimeout := e.duration("ACME_PROXY_PUBLIC_ORDER_TIMEOUT", 10*time.Minute)

	publicDirectory := e.optional("ACME_PROXY_PUBLIC_CA_DIRECTORY", letsEncryptStaging)
	publicContact := e.required("ACME_PROXY_PUBLIC_CONTACT")
	agreeTOS := e.optional("ACME_PROXY_PUBLIC_AGREE_TOS", "") == "true"
	dnsProvider := e.required("ACME_PROXY_DNS_PROVIDER")
	publicResolvers := e.list("ACME_PROXY_PUBLIC_RESOLVERS")
	propagationWait := e.duration("ACME_PROXY_PUBLIC_PROPAGATION_WAIT", 0)
	if len(e.errs) > 0 {
		return fmt.Errorf("configuration: %w", errors.Join(e.errs...))
	}

	if err := os.MkdirAll(stateDir, 0o700); err != nil {
		return fmt.Errorf("creating state dir: %w", err)
	}

	internalCfg := acme.Config{
		InternalDomain:     internalDomain,
		WildcardBases:      wildcardBases,
		DatabasePath:       filepath.Join(stateDir, "acme-proxy.db"),
		OrderLifetime:      orderLifetime,
		ChallengeTimeout:   challengeTimeout,
		PublicOrderTimeout: publicOrderTimeout,
	}
	// Check the Internal side's configuration before touching the Public CA.
	if err := internalCfg.Validate(); err != nil {
		return fmt.Errorf("configuration: %w", err)
	}

	if publicDirectory == letsEncryptStaging {
		logger.Warn("using Let's Encrypt STAGING; set ACME_PROXY_PUBLIC_CA_DIRECTORY for publicly trusted certificates")
	}
	pub, err := public.New(public.Config{
		DirectoryURL:    publicDirectory,
		Contact:         publicContact,
		AgreeToTOS:      agreeTOS,
		DNSProvider:     dnsProvider,
		Resolvers:       publicResolvers,
		PropagationWait: propagationWait,
		StateDir:        stateDir,
		Logger:          logger.With("side", "public"),
	})
	if err != nil {
		return err
	}

	srv, err := acme.New(internalCfg, acme.Dependencies{
		Public:      pub,
		DialContext: acme.NewChallengeDialer(challengeResolver),
		Logger:      logger.With("side", "internal"),
	})
	if err != nil {
		return err
	}
	defer srv.Close()

	r := chi.NewRouter()
	r.Use(middleware.RequestID)
	r.Use(middleware.Logger)
	r.Use(middleware.Recoverer)
	r.Get("/", func(w http.ResponseWriter, _ *http.Request) {
		_, _ = w.Write([]byte("acme-proxy for " + internalDomain + ": ACME directory at " + acme.PathPrefix + "directory\n"))
	})
	r.Mount("/", srv.Handler())

	httpSrv := &http.Server{
		Addr:              listen,
		Handler:           r,
		ReadHeaderTimeout: 10 * time.Second,
	}

	ctx, stop := signal.NotifyContext(context.Background(), syscall.SIGINT, syscall.SIGTERM)
	defer stop()
	errc := make(chan error, 1)
	go func() {
		logger.Info("acme-proxy listening", "addr", listen, "internal_domain", internalDomain,
			"wildcard_bases", wildcardBases, "public_ca", publicDirectory, "dns_provider", dnsProvider)
		errc <- httpSrv.ListenAndServeTLS(tlsCert, tlsKey)
	}()

	select {
	case err := <-errc:
		return err
	case <-ctx.Done():
		logger.Info("shutting down")
		shutdownCtx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
		defer cancel()
		return httpSrv.Shutdown(shutdownCtx)
	}
}
