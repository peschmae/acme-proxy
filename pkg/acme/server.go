package acme

import (
	"context"
	"encoding/json"
	"fmt"
	"log/slog"
	"net"
	"net/http"
	"strings"
	"sync"

	"github.com/go-chi/chi/v5"
)

// PathPrefix is where the Internal ACME server is served.
const PathPrefix = "/acme/"

// Dependencies are the outward-facing collaborators of the Internal side.
type Dependencies struct {
	// Public is the Public side. Required.
	Public PublicCA
	// DialContext is used to connect to Requesters for HTTP-01 Internal
	// Challenges. Nil means a plain net.Dialer using the system resolver.
	DialContext func(ctx context.Context, network, addr string) (net.Conn, error)
	// Logger defaults to slog.Default().
	Logger *slog.Logger
}

// Server is the Internal ACME server of one acme-proxy instance.
type Server struct {
	cfg    Config
	store  *store
	public PublicCA
	dial   func(ctx context.Context, network, addr string) (net.Conn, error)
	log    *slog.Logger

	// mu serialises read-modify-write cycles on orders, authorizations and
	// challenges.
	mu sync.Mutex

	bgCtx    context.Context
	bgCancel context.CancelFunc
	bg       sync.WaitGroup
}

// New validates cfg, opens the database and returns a ready Server.
func New(cfg Config, deps Dependencies) (*Server, error) {
	if err := cfg.Validate(); err != nil {
		return nil, fmt.Errorf("invalid configuration: %w", err)
	}
	cfg = cfg.withDefaults()
	if deps.Public == nil {
		return nil, fmt.Errorf("a PublicCA implementation is required")
	}
	st, err := openStore(cfg.DatabasePath)
	if err != nil {
		return nil, err
	}
	s := &Server{
		cfg:    cfg,
		store:  st,
		public: deps.Public,
		dial:   deps.DialContext,
		log:    deps.Logger,
	}
	if s.dial == nil {
		s.dial = (&net.Dialer{}).DialContext
	}
	if s.log == nil {
		s.log = slog.Default()
	}
	s.bgCtx, s.bgCancel = context.WithCancel(context.Background())
	if err := s.recoverProcessingOrders(); err != nil {
		st.Close()
		return nil, err
	}
	return s, nil
}

// Close stops background work and closes the database.
func (s *Server) Close() error {
	s.bgCancel()
	s.bg.Wait()
	return s.store.Close()
}

// Handler returns the HTTP handler serving the Internal ACME API under PathPrefix.
func (s *Server) Handler() http.Handler {
	r := chi.NewRouter()
	r.Route(strings.TrimSuffix(PathPrefix, "/"), func(r chi.Router) {
		r.Get("/directory", s.directory)
		r.Head("/new-nonce", s.withNonce(s.newNonce))
		r.Get("/new-nonce", s.withNonce(s.newNonce))

		r.Post("/new-account", s.byJWK(s.newAccount))
		r.Post("/account/{accID}", s.byKid(s.account))
		r.Post("/account/{accID}/orders", s.byKid(postAsGet(s.accountOrders)))

		r.Post("/new-order", s.byKid(s.newOrder))
		r.Post("/order/{orderID}", s.byKid(postAsGet(s.getOrder)))
		r.Post("/order/{orderID}/finalize", s.byKid(s.finalizeOrder))
		r.Post("/authorization/{authzID}", s.byKid(s.authorization))
		r.Post("/challenge/{challID}", s.byKid(s.challenge))
		r.Post("/certificate/{certID}", s.byKid(postAsGet(s.certificate)))

		r.Post("/revoke-cert", s.byKidOrJWK(s.revokeCert))
		r.Post("/key-change", s.withNonce(s.keyChange))
	})
	return r
}

// baseURL returns the absolute URL of PathPrefix as seen by the Requester.
func baseURL(r *http.Request) string {
	scheme := "https"
	if r.TLS == nil {
		scheme = "http"
	}
	return scheme + "://" + r.Host + PathPrefix
}

func linkURL(r *http.Request, parts ...string) string {
	return baseURL(r) + strings.Join(parts, "/")
}

func (s *Server) directory(w http.ResponseWriter, r *http.Request) {
	writeJSON(w, http.StatusOK, map[string]any{
		"newNonce":   linkURL(r, "new-nonce"),
		"newAccount": linkURL(r, "new-account"),
		"newOrder":   linkURL(r, "new-order"),
		"revokeCert": linkURL(r, "revoke-cert"),
		"keyChange":  linkURL(r, "key-change"),
		"meta": map[string]any{
			"externalAccountRequired": false,
		},
	})
}

// newNonce implements RFC 8555 §7.2.
func (s *Server) newNonce(w http.ResponseWriter, r *http.Request) {
	if r.Method == http.MethodGet {
		w.WriteHeader(http.StatusNoContent)
		return
	}
	w.WriteHeader(http.StatusOK)
}

func (s *Server) keyChange(w http.ResponseWriter, r *http.Request) {
	writeProblem(w, NewProblem(http.StatusNotImplemented, "malformed",
		"key-change is not supported by acme-proxy; create a new Internal Account with the new key instead"))
}

func writeJSON(w http.ResponseWriter, status int, v any) {
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(status)
	_ = json.NewEncoder(w).Encode(v)
}
