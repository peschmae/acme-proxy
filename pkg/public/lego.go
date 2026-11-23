// Package public implements acme-proxy's Public side with lego: the Public
// Account, Public Orders, and DNS-01 Public Challenges through the DNS Provider.
package public

import (
	"context"
	"crypto"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/x509"
	"encoding/json"
	"encoding/pem"
	"errors"
	"fmt"
	"log/slog"
	"net/url"
	"os"
	"path/filepath"
	"regexp"
	"strings"
	"time"

	legoacme "github.com/go-acme/lego/v4/acme"
	"github.com/go-acme/lego/v4/certificate"
	"github.com/go-acme/lego/v4/challenge/dns01"
	"github.com/go-acme/lego/v4/lego"
	legolog "github.com/go-acme/lego/v4/log"
	"github.com/go-acme/lego/v4/registration"

	"github.com/peschmae/acme-proxy/pkg/acme"
)

// Config configures the Public side.
type Config struct {
	// DirectoryURL selects the Public CA, e.g. Let's Encrypt staging or production.
	DirectoryURL string
	// Contact is the Public Account's email address.
	Contact string
	// AgreeToTOS must be true: registering requires agreeing to the Public
	// CA's terms of service.
	AgreeToTOS bool
	// DNSProvider is a supported lego DNS provider name (see
	// SupportedDNSProviders). Its credentials are read from that provider's
	// environment variables.
	DNSProvider string
	// Resolvers are public recursive DNS servers used to find the Internal
	// Domain's public zone and to check Public Challenge propagation. They
	// must not be the internal resolvers. Default: 1.1.1.1:53, 8.8.8.8:53.
	Resolvers []string
	// PropagationWait, if set, skips lego's DNS propagation check and waits
	// this long after writing the TXT record instead. Use it when acme-proxy
	// cannot query public DNS (e.g. outbound DNS is blocked).
	PropagationWait time.Duration
	// StateDir holds the Public Account key and registration.
	StateDir string
	Logger   *slog.Logger
}

// DefaultResolvers are used when Config.Resolvers is empty.
var DefaultResolvers = []string{"1.1.1.1:53", "8.8.8.8:53"}

// Lego is the lego-backed acme.PublicCA.
type Lego struct {
	client *lego.Client
	log    *slog.Logger
	// sem serialises Public Orders so concurrent orders for the same name
	// never race on the same _acme-challenge TXT record.
	sem chan struct{}
}

var _ acme.PublicCA = (*Lego)(nil)

// New loads or registers the Public Account and prepares DNS-01.
func New(cfg Config) (*Lego, error) {
	if cfg.DirectoryURL == "" {
		return nil, errors.New("public CA directory URL must be set")
	}
	if !cfg.AgreeToTOS {
		return nil, errors.New("you must agree to the Public CA's terms of service")
	}
	if cfg.Contact == "" {
		return nil, errors.New("public account contact email must be set")
	}
	if cfg.DNSProvider == "" {
		return nil, errors.New("DNS provider must be set")
	}
	if cfg.Logger == nil {
		cfg.Logger = slog.Default()
	}
	if len(cfg.Resolvers) == 0 {
		cfg.Resolvers = DefaultResolvers
	}
	legolog.Logger = slog.NewLogLogger(cfg.Logger.With("component", "lego").Handler(), slog.LevelInfo)

	u, err := loadOrCreateUser(cfg)
	if err != nil {
		return nil, err
	}
	lc := lego.NewConfig(u)
	lc.CADirURL = cfg.DirectoryURL
	lc.UserAgent = "acme-proxy"
	client, err := lego.NewClient(lc)
	if err != nil {
		return nil, fmt.Errorf("creating Public CA client: %w", err)
	}

	provider, err := newDNSProvider(cfg.DNSProvider)
	if err != nil {
		return nil, fmt.Errorf("DNS provider %q: %w", cfg.DNSProvider, err)
	}
	opts := []dns01.ChallengeOption{dns01.AddRecursiveNameservers(cfg.Resolvers)}
	if cfg.PropagationWait > 0 {
		opts = append(opts, dns01.PropagationWait(cfg.PropagationWait, true))
	}
	if err := client.Challenge.SetDNS01Provider(provider, opts...); err != nil {
		return nil, fmt.Errorf("configuring DNS-01: %w", err)
	}

	if u.Registration == nil {
		reg, err := client.Registration.Register(registration.RegisterOptions{TermsOfServiceAgreed: true})
		if err != nil {
			return nil, fmt.Errorf("registering Public Account: %w", err)
		}
		u.Registration = reg
		if err := u.save(); err != nil {
			return nil, err
		}
		cfg.Logger.Info("public account registered", "account", reg.URI, "directory", cfg.DirectoryURL)
	} else {
		cfg.Logger.Info("public account loaded", "account", u.Registration.URI, "directory", cfg.DirectoryURL)
	}

	return &Lego{client: client, log: cfg.Logger, sem: make(chan struct{}, 1)}, nil
}

// Issue places one Public Order for the CSR and returns the bundled PEM chain.
func (l *Lego) Issue(ctx context.Context, csrDER []byte, ids []acme.Identifier) ([]byte, error) {
	csr, err := x509.ParseCertificateRequest(csrDER)
	if err != nil {
		return nil, fmt.Errorf("parsing csr: %w", err)
	}
	log := l.log.With("order", acme.OrderIDFrom(ctx), "identifiers", values(ids))

	select {
	case l.sem <- struct{}{}:
	case <-ctx.Done():
		return nil, ctx.Err()
	}

	type result struct {
		res *certificate.Resource
		err error
	}
	done := make(chan result, 1)
	start := time.Now()
	log.Info("public order started")
	go func() {
		// lego has no context support; the semaphore is released only when
		// it really finishes, even if the caller gave up.
		defer func() { <-l.sem }()
		res, err := l.client.Certificate.ObtainForCSR(certificate.ObtainForCSRRequest{CSR: csr, Bundle: true})
		done <- result{res, err}
	}()

	select {
	case <-ctx.Done():
		log.Warn("gave up waiting for public order", "error", ctx.Err())
		return nil, ctx.Err()
	case r := <-done:
		if r.err != nil {
			log.Warn("public order failed", "error", r.err, "duration", time.Since(start))
			return nil, toProblem(r.err)
		}
		log.Info("public order valid", "certificate", r.res.CertStableURL, "duration", time.Since(start))
		return r.res.Certificate, nil
	}
}

// Revoke revokes a certificate through the Public Account.
func (l *Lego) Revoke(ctx context.Context, certDER []byte, reason int) error {
	certPEM := pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: certDER})
	r := uint(reason)
	done := make(chan error, 1)
	go func() { done <- l.client.Certificate.RevokeWithReason(certPEM, &r) }()
	select {
	case <-ctx.Done():
		return ctx.Err()
	case err := <-done:
		if err != nil {
			return toProblem(err)
		}
		return nil
	}
}

// toProblem passes a Public CA problem document through unchanged; other
// failures (DNS Provider, propagation, network) become serverInternal.
func toProblem(err error) error {
	var pd *legoacme.ProblemDetails
	if errors.As(err, &pd) {
		p := &acme.Problem{Type: pd.Type, Detail: pd.Detail, Status: pd.HTTPStatus}
		for _, sp := range pd.SubProblems {
			sub := &acme.Problem{Type: sp.Type, Detail: sp.Detail}
			if sp.Identifier.Value != "" {
				sub.Identifier = &acme.Identifier{Type: acme.IdentifierType(sp.Identifier.Type), Value: sp.Identifier.Value}
			}
			p.Subproblems = append(p.Subproblems, sub)
		}
		return p
	}
	return acme.NewProblem(500, "serverInternal", "public order failed: %s", strings.TrimSpace(err.Error()))
}

func values(ids []acme.Identifier) []string {
	out := make([]string, len(ids))
	for i, id := range ids {
		out[i] = id.Value
	}
	return out
}

// --- Public Account persistence ---------------------------------------------

type user struct {
	path         string
	Email        string                 `json:"email"`
	Directory    string                 `json:"directory"`
	KeyPEM       string                 `json:"key"`
	Registration *registration.Resource `json:"registration,omitempty"`
	key          crypto.PrivateKey
}

func (u *user) GetEmail() string                        { return u.Email }
func (u *user) GetRegistration() *registration.Resource { return u.Registration }
func (u *user) GetPrivateKey() crypto.PrivateKey        { return u.key }

var unsafeChars = regexp.MustCompile(`[^a-zA-Z0-9.-]+`)

// accountPath gives each Public CA directory its own account file, so
// switching between staging and production keeps both accounts.
func accountPath(stateDir, directory string) string {
	name := directory
	if u, err := url.Parse(directory); err == nil {
		name = u.Host + u.Path
	}
	name = strings.Trim(unsafeChars.ReplaceAllString(name, "_"), "_")
	return filepath.Join(stateDir, "public-account-"+name+".json")
}

func loadOrCreateUser(cfg Config) (*user, error) {
	if err := os.MkdirAll(cfg.StateDir, 0o700); err != nil {
		return nil, fmt.Errorf("creating state dir: %w", err)
	}
	path := accountPath(cfg.StateDir, cfg.DirectoryURL)
	u := &user{path: path}

	b, err := os.ReadFile(path)
	switch {
	case errors.Is(err, os.ErrNotExist):
		key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
		if err != nil {
			return nil, err
		}
		der, err := x509.MarshalPKCS8PrivateKey(key)
		if err != nil {
			return nil, err
		}
		u.Email, u.Directory, u.key = cfg.Contact, cfg.DirectoryURL, key
		u.KeyPEM = string(pem.EncodeToMemory(&pem.Block{Type: "PRIVATE KEY", Bytes: der}))
		return u, u.save()
	case err != nil:
		return nil, fmt.Errorf("reading Public Account: %w", err)
	}

	if err := json.Unmarshal(b, u); err != nil {
		return nil, fmt.Errorf("parsing Public Account %s: %w", path, err)
	}
	block, _ := pem.Decode([]byte(u.KeyPEM))
	if block == nil {
		return nil, fmt.Errorf("Public Account %s has no key", path)
	}
	if u.key, err = x509.ParsePKCS8PrivateKey(block.Bytes); err != nil {
		return nil, fmt.Errorf("parsing Public Account key: %w", err)
	}
	u.Email = cfg.Contact
	return u, nil
}

func (u *user) save() error {
	b, err := json.MarshalIndent(u, "", "  ")
	if err != nil {
		return err
	}
	tmp := u.path + ".tmp"
	if err := os.WriteFile(tmp, b, 0o600); err != nil {
		return fmt.Errorf("writing Public Account: %w", err)
	}
	return os.Rename(tmp, u.path)
}
