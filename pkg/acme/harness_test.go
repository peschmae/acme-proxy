package acme_test

import (
	"bytes"
	"context"
	"crypto"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/json"
	"encoding/pem"
	"errors"
	"io"
	"log/slog"
	"math/big"
	"net"
	"net/http"
	"net/http/httptest"
	"path/filepath"
	"sync"
	"sync/atomic"
	"syscall"
	"testing"
	"time"

	jose "github.com/go-jose/go-jose/v3"
	xacme "golang.org/x/crypto/acme"

	"github.com/peschmae/acme-proxy/pkg/acme"
)

const internalDomain = "example.biz"

// harness runs one acme-proxy Internal ACME server in-process, with a fake
// Public side and fake Requester hosts behind the Internal Challenge dialer.
type harness struct {
	t       *testing.T
	cfg     acme.Config
	srv     *acme.Server
	handler atomic.Value // http.Handler
	ts      *httptest.Server
	public  *fakePublic
	hosts   *fakeHosts
}

func newHarness(t *testing.T, mods ...func(*acme.Config)) *harness {
	t.Helper()
	h := &harness{
		t: t,
		cfg: acme.Config{
			InternalDomain: internalDomain,
			WildcardBases:  []string{"wild." + internalDomain},
			DatabasePath:   filepath.Join(t.TempDir(), "acme.db"),
		},
		public: newFakePublic(t),
		hosts:  newFakeHosts(t),
	}
	for _, m := range mods {
		m(&h.cfg)
	}
	h.start()
	h.ts = httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		h.handler.Load().(http.Handler).ServeHTTP(w, r)
	}))
	t.Cleanup(func() {
		h.ts.Close()
		h.public.releaseAll()
		h.srv.Close()
	})
	return h
}

func (h *harness) start() {
	h.t.Helper()
	srv, err := acme.New(h.cfg, acme.Dependencies{
		Public:      h.public,
		DialContext: h.hosts.dial,
		Logger:      slog.New(slog.NewTextHandler(io.Discard, nil)),
	})
	if err != nil {
		h.t.Fatalf("acme.New: %v", err)
	}
	h.srv = srv
	h.handler.Store(srv.Handler())
}

// restart stops the server (as a process exit would) and starts a new one on
// the same database and URL.
func (h *harness) restart() {
	h.t.Helper()
	if err := h.srv.Close(); err != nil {
		h.t.Fatalf("close: %v", err)
	}
	h.start()
}

func (h *harness) directoryURL() string { return h.ts.URL + acme.PathPrefix + "directory" }

func ctx(t *testing.T) context.Context {
	c, cancel := context.WithTimeout(context.Background(), 20*time.Second)
	t.Cleanup(cancel)
	return c
}

// newClient returns an unregistered Requester ACME client.
func (h *harness) newClient() *xacme.Client {
	h.t.Helper()
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		h.t.Fatal(err)
	}
	return &xacme.Client{Key: key, DirectoryURL: h.directoryURL(), HTTPClient: h.ts.Client()}
}

// register returns a Requester with a fresh Internal Account.
func (h *harness) register() *xacme.Client {
	h.t.Helper()
	c := h.newClient()
	if _, err := c.Register(ctx(h.t), &xacme.Account{Contact: []string{"mailto:ops@example.biz"}}, xacme.AcceptTOS); err != nil {
		h.t.Fatalf("register: %v", err)
	}
	return c
}

// authorize serves the key authorization on each authorization's host and
// lets acme-proxy check it, returning the order once ready.
func (h *harness) authorize(c *xacme.Client, names ...string) *xacme.Order {
	h.t.Helper()
	o, err := c.AuthorizeOrder(ctx(h.t), xacme.DomainIDs(names...))
	if err != nil {
		h.t.Fatalf("new order %v: %v", names, err)
	}
	for _, u := range o.AuthzURLs {
		h.solve(c, u)
	}
	o, err = c.WaitOrder(ctx(h.t), o.URI)
	if err != nil {
		h.t.Fatalf("wait order: %v", err)
	}
	return o
}

// solve answers the http-01 challenge of one authorization correctly.
func (h *harness) solve(c *xacme.Client, authzURL string) {
	h.t.Helper()
	az, err := c.GetAuthorization(ctx(h.t), authzURL)
	if err != nil {
		h.t.Fatalf("get authorization: %v", err)
	}
	ch := http01(h.t, az)
	keyAuth, err := c.HTTP01ChallengeResponse(ch.Token)
	if err != nil {
		h.t.Fatal(err)
	}
	h.hosts.serve(az.Identifier.Value, ch.Token, keyAuth)
	if _, err := c.Accept(ctx(h.t), ch); err != nil {
		h.t.Fatalf("accept: %v", err)
	}
	if _, err := c.WaitAuthorization(ctx(h.t), authzURL); err != nil {
		h.t.Fatalf("wait authorization: %v", err)
	}
}

func http01(t *testing.T, az *xacme.Authorization) *xacme.Challenge {
	t.Helper()
	if len(az.Challenges) != 1 || az.Challenges[0].Type != "http-01" {
		t.Fatalf("expected exactly one http-01 challenge, got %+v", az.Challenges)
	}
	return az.Challenges[0]
}

// newCSR returns a CSR (DER) for names and its key.
func newCSR(t *testing.T, names ...string) ([]byte, crypto.Signer) {
	t.Helper()
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	der, err := x509.CreateCertificateRequest(rand.Reader, &x509.CertificateRequest{DNSNames: names}, key)
	if err != nil {
		t.Fatal(err)
	}
	return der, key
}

// obtain runs the whole flow and returns the DER chain and the leaf key.
func (h *harness) obtain(c *xacme.Client, names ...string) ([][]byte, crypto.Signer) {
	h.t.Helper()
	o := h.authorize(c, names...)
	csr, key := newCSR(h.t, names...)
	chain, _, err := c.CreateOrderCert(ctx(h.t), o.FinalizeURL, csr, true)
	if err != nil {
		h.t.Fatalf("finalize: %v", err)
	}
	return chain, key
}

func problemType(err error) string {
	var e *xacme.Error
	if errors.As(err, &e) {
		return e.ProblemType
	}
	return ""
}

func wantProblem(t *testing.T, err error, typ string) {
	t.Helper()
	if err == nil {
		t.Fatalf("expected %s error, got success", typ)
	}
	if got := problemType(err); got != "urn:ietf:params:acme:error:"+typ {
		t.Fatalf("expected problem %s, got %q (%v)", typ, got, err)
	}
}

// rawResponse is a raw ACME response.
type rawResponse struct {
	Status int
	Header http.Header
	Body   []byte
}

func (r rawResponse) json(t *testing.T) map[string]any {
	t.Helper()
	var m map[string]any
	if err := json.Unmarshal(r.Body, &m); err != nil {
		t.Fatalf("decoding %s: %v", r.Body, err)
	}
	return m
}

// post sends a JWS-signed request with arbitrary payload (nil = POST-as-GET).
// With kid == "" the key is embedded as jwk.
func (h *harness) post(key crypto.Signer, kid, url string, payload any) rawResponse {
	h.t.Helper()
	res, err := h.ts.Client().Head(h.ts.URL + acme.PathPrefix + "new-nonce")
	if err != nil {
		h.t.Fatal(err)
	}
	res.Body.Close()
	nonce := res.Header.Get("Replay-Nonce")

	opts := &jose.SignerOptions{ExtraHeaders: map[jose.HeaderKey]any{"nonce": nonce, "url": url}}
	sk := jose.SigningKey{Algorithm: jose.ES256, Key: jose.JSONWebKey{Key: key, KeyID: kid}}
	if kid == "" {
		opts.EmbedJWK = true
		sk.Key = key
	}
	signer, err := jose.NewSigner(sk, opts)
	if err != nil {
		h.t.Fatal(err)
	}
	var body []byte
	if payload != nil {
		if body, err = json.Marshal(payload); err != nil {
			h.t.Fatal(err)
		}
	}
	jws, err := signer.Sign(body)
	if err != nil {
		h.t.Fatal(err)
	}
	// go-jose omits an empty payload; ACME's POST-as-GET needs "payload": "".
	var flat map[string]any
	if err := json.Unmarshal([]byte(jws.FullSerialize()), &flat); err != nil {
		h.t.Fatal(err)
	}
	if _, ok := flat["payload"]; !ok {
		flat["payload"] = ""
	}
	raw, _ := json.Marshal(flat)
	req, _ := http.NewRequest(http.MethodPost, url, bytes.NewReader(raw))
	req.Header.Set("Content-Type", "application/jose+json")
	res, err = h.ts.Client().Do(req)
	if err != nil {
		h.t.Fatal(err)
	}
	defer res.Body.Close()
	b, _ := io.ReadAll(res.Body)
	return rawResponse{Status: res.StatusCode, Header: res.Header, Body: b}
}

// --- fake Public side -------------------------------------------------------

type issueCall struct {
	CSR         []byte
	Identifiers []acme.Identifier
}

type revokeCall struct {
	Cert   []byte
	Reason int
}

type fakePublic struct {
	t  *testing.T
	ca *testCA

	mu      sync.Mutex
	issued  []issueCall
	revoked []revokeCall
	// failWith makes Issue fail with this error.
	failWith error
	// block makes Issue wait until released (or its context ends).
	block   chan struct{}
	started chan struct{}
}

func newFakePublic(t *testing.T) *fakePublic {
	return &fakePublic{t: t, ca: newTestCA(t), started: make(chan struct{}, 16)}
}

func (f *fakePublic) Issue(ctx context.Context, csrDER []byte, ids []acme.Identifier) ([]byte, error) {
	f.mu.Lock()
	f.issued = append(f.issued, issueCall{CSR: append([]byte(nil), csrDER...), Identifiers: ids})
	block, failWith := f.block, f.failWith
	f.mu.Unlock()
	select {
	case f.started <- struct{}{}:
	default:
	}
	if block != nil {
		select {
		case <-block:
		case <-ctx.Done():
			return nil, ctx.Err()
		}
	}
	if failWith != nil {
		return nil, failWith
	}
	return f.ca.sign(csrDER)
}

func (f *fakePublic) Revoke(_ context.Context, der []byte, reason int) error {
	f.mu.Lock()
	defer f.mu.Unlock()
	f.revoked = append(f.revoked, revokeCall{Cert: der, Reason: reason})
	return nil
}

func (f *fakePublic) setBlocking() {
	f.mu.Lock()
	defer f.mu.Unlock()
	f.block = make(chan struct{})
}

func (f *fakePublic) releaseAll() {
	f.mu.Lock()
	defer f.mu.Unlock()
	if f.block != nil {
		select {
		case <-f.block:
		default:
			close(f.block)
		}
	}
}

func (f *fakePublic) issueCalls() []issueCall {
	f.mu.Lock()
	defer f.mu.Unlock()
	return append([]issueCall(nil), f.issued...)
}

func (f *fakePublic) revokeCalls() []revokeCall {
	f.mu.Lock()
	defer f.mu.Unlock()
	return append([]revokeCall(nil), f.revoked...)
}

type testCA struct {
	cert *x509.Certificate
	key  *ecdsa.PrivateKey
	der  []byte
}

func newTestCA(t *testing.T) *testCA {
	t.Helper()
	key, _ := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	tmpl := &x509.Certificate{
		SerialNumber:          big.NewInt(1),
		Subject:               pkix.Name{CommonName: "fake Public CA"},
		NotBefore:             time.Now().Add(-time.Hour),
		NotAfter:              time.Now().Add(24 * time.Hour),
		IsCA:                  true,
		BasicConstraintsValid: true,
		KeyUsage:              x509.KeyUsageCertSign,
	}
	der, err := x509.CreateCertificate(rand.Reader, tmpl, tmpl, &key.PublicKey, key)
	if err != nil {
		t.Fatal(err)
	}
	cert, _ := x509.ParseCertificate(der)
	return &testCA{cert: cert, key: key, der: der}
}

func (ca *testCA) sign(csrDER []byte) ([]byte, error) {
	csr, err := x509.ParseCertificateRequest(csrDER)
	if err != nil {
		return nil, err
	}
	serial, _ := rand.Int(rand.Reader, new(big.Int).Lsh(big.NewInt(1), 64))
	tmpl := &x509.Certificate{
		SerialNumber: serial,
		DNSNames:     csr.DNSNames,
		NotBefore:    time.Now().Add(-time.Minute),
		NotAfter:     time.Now().Add(90 * 24 * time.Hour),
		ExtKeyUsage:  []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth},
	}
	der, err := x509.CreateCertificate(rand.Reader, tmpl, ca.cert, csr.PublicKey, ca.key)
	if err != nil {
		return nil, err
	}
	var buf bytes.Buffer
	pem.Encode(&buf, &pem.Block{Type: "CERTIFICATE", Bytes: der})
	pem.Encode(&buf, &pem.Block{Type: "CERTIFICATE", Bytes: ca.der})
	return buf.Bytes(), nil
}

// --- fake Requester hosts ---------------------------------------------------

// fakeHosts plays the internal network: each known host name maps to a local
// HTTP server that serves key authorizations by token.
type fakeHosts struct {
	t         *testing.T
	mu        sync.Mutex
	servers   map[string]*httptest.Server
	tokens    map[string]map[string]string // host -> token -> body
	refuse    map[string]bool
	redirects map[string]string // host -> redirect target
	dialed    []string
}

func newFakeHosts(t *testing.T) *fakeHosts {
	return &fakeHosts{t: t, servers: map[string]*httptest.Server{}, tokens: map[string]map[string]string{}, refuse: map[string]bool{}, redirects: map[string]string{}}
}

// serve makes host answer /.well-known/acme-challenge/token with body.
func (f *fakeHosts) serve(host, token, body string) {
	f.mu.Lock()
	defer f.mu.Unlock()
	if f.tokens[host] == nil {
		f.tokens[host] = map[string]string{}
	}
	f.tokens[host][token] = body
	if f.servers[host] != nil {
		return
	}
	mux := http.NewServeMux()
	mux.HandleFunc("/.well-known/acme-challenge/", func(w http.ResponseWriter, r *http.Request) {
		tok := r.URL.Path[len("/.well-known/acme-challenge/"):]
		f.mu.Lock()
		b, ok := f.tokens[host][tok]
		target := f.redirects[host]
		f.mu.Unlock()
		if target != "" {
			http.Redirect(w, r, target+r.URL.Path, http.StatusFound)
			return
		}
		if !ok {
			http.NotFound(w, r)
			return
		}
		io.WriteString(w, b)
	})
	srv := httptest.NewServer(mux)
	f.t.Cleanup(srv.Close)
	f.servers[host] = srv
}

// redirect makes host answer challenge requests with a redirect to target.
func (f *fakeHosts) redirect(host, target string) {
	f.serve(host, "-", "-")
	f.mu.Lock()
	defer f.mu.Unlock()
	f.redirects[host] = target
}

// exists makes host resolvable and reachable, serving nothing.
func (f *fakeHosts) exists(host string) { f.serve(host, "-", "-") }

// refuseConnections makes host resolvable but refuse connections.
func (f *fakeHosts) refuseConnections(host string) {
	f.mu.Lock()
	defer f.mu.Unlock()
	f.refuse[host] = true
}

func (f *fakeHosts) dial(ctx context.Context, network, addr string) (net.Conn, error) {
	host, port, err := net.SplitHostPort(addr)
	if err != nil {
		return nil, err
	}
	f.mu.Lock()
	f.dialed = append(f.dialed, addr)
	srv, refuse := f.servers[host], f.refuse[host]
	f.mu.Unlock()
	if port != "80" {
		return nil, &net.OpError{Op: "dial", Net: network, Err: syscall.ECONNREFUSED}
	}
	if refuse {
		return nil, &net.OpError{Op: "dial", Net: network, Err: syscall.ECONNREFUSED}
	}
	if srv == nil {
		return nil, &net.OpError{Op: "dial", Net: network, Err: &net.DNSError{Err: "no such host", Name: host, IsNotFound: true}}
	}
	return (&net.Dialer{}).DialContext(ctx, network, srv.Listener.Addr().String())
}

func (f *fakeHosts) dialedAddrs() []string {
	f.mu.Lock()
	defer f.mu.Unlock()
	return append([]string(nil), f.dialed...)
}
