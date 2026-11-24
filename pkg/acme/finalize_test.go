package acme_test

import (
	"bytes"
	"crypto"
	"crypto/x509"
	"errors"
	"net/http"
	"testing"
	"time"

	xacme "golang.org/x/crypto/acme"

	"github.com/peschmae/acme-proxy/pkg/acme"
)

func TestFullFlowIssuesCertificateFromForwardedCSR(t *testing.T) {
	h := newHarness(t)
	c := h.register()

	o := h.authorize(c, "app.example.biz", "*.wild.example.biz")
	if n := len(h.public.issueCalls()); n != 0 {
		t.Fatalf("no Public Order may exist before finalize, got %d", n)
	}

	csr, key := newCSR(t, "app.example.biz", "*.wild.example.biz")
	chain, certURL, err := c.CreateOrderCert(ctx(t), o.FinalizeURL, csr, true)
	if err != nil {
		t.Fatalf("finalize: %v", err)
	}
	if len(chain) != 2 {
		t.Fatalf("expected leaf + intermediate, got %d certificates", len(chain))
	}
	leaf, err := x509.ParseCertificate(chain[0])
	if err != nil {
		t.Fatal(err)
	}
	if !leaf.PublicKey.(interface{ Equal(crypto.PublicKey) bool }).Equal(key.Public()) {
		t.Fatal("certificate is not for the Requester's key")
	}

	calls := h.public.issueCalls()
	if len(calls) != 1 {
		t.Fatalf("expected exactly one Public Order, got %d", len(calls))
	}
	if !bytes.Equal(calls[0].CSR, csr) {
		t.Fatal("CSR was not forwarded unchanged")
	}

	// Download again via the certificate URL.
	again, err := c.FetchCert(ctx(t), certURL, true)
	if err != nil || !bytes.Equal(again[0], chain[0]) {
		t.Fatalf("fetch certificate: %v", err)
	}

	got, _ := c.GetOrder(ctx(t), o.URI)
	if got.Status != xacme.StatusValid || got.CertURL != certURL {
		t.Fatalf("expected valid order with certificate URL, got %+v", got)
	}
}

func TestFinalizeReturnsProcessingWithRetryAfter(t *testing.T) {
	h := newHarness(t)
	h.public.setBlocking()
	c := h.register()
	o := h.authorize(c, "app.example.biz")
	csr, _ := newCSR(t, "app.example.biz")
	acc, _ := c.GetReg(ctx(t), "")

	res := h.post(c.Key, acc.URI, o.FinalizeURL, map[string]string{"csr": b64(csr)})
	if res.Status != http.StatusOK || res.json(t)["status"] != "processing" || res.Header.Get("Retry-After") == "" {
		t.Fatalf("expected processing with Retry-After, got %d %v %s", res.Status, res.Header, res.Body)
	}
	<-h.public.started
	res = h.post(c.Key, acc.URI, o.URI, nil)
	if res.json(t)["status"] != "processing" || res.Header.Get("Retry-After") == "" {
		t.Fatalf("expected order to stay processing while the Public Order runs, got %s", res.Body)
	}

	h.public.releaseAll()
	got, err := c.WaitOrder(ctx(t), o.URI)
	if err != nil || got.Status != xacme.StatusValid {
		t.Fatalf("expected valid after release, got %+v %v", got, err)
	}
}

func TestPublicOrderFailureIsPassedThrough(t *testing.T) {
	h := newHarness(t)
	h.public.failWith = &acme.Problem{
		Type:   "urn:ietf:params:acme:error:rateLimited",
		Detail: "too many certificates already issued for example.biz",
		Status: http.StatusTooManyRequests,
	}
	c := h.register()
	o := h.authorize(c, "app.example.biz")
	csr, _ := newCSR(t, "app.example.biz")
	_, _, err := c.CreateOrderCert(ctx(t), o.FinalizeURL, csr, true)
	var oe *xacme.OrderError
	if !errors.As(err, &oe) {
		t.Fatalf("expected order error, got %v", err)
	}

	got, _ := c.GetOrder(ctx(t), o.URI)
	if got.Status != xacme.StatusInvalid || got.Error == nil {
		t.Fatalf("expected invalid order with error, got %+v", got)
	}
	if got.Error.ProblemType != "urn:ietf:params:acme:error:rateLimited" || got.Error.Detail != "too many certificates already issued for example.biz" {
		t.Fatalf("Public CA problem not passed through: %+v", got.Error)
	}

	time.Sleep(100 * time.Millisecond)
	if n := len(h.public.issueCalls()); n != 1 {
		t.Fatalf("failed Public Orders must not be retried, got %d calls", n)
	}
}

func TestFinalizeRejectsCSRWithDifferentNames(t *testing.T) {
	cases := map[string][]string{
		"extra name":   {"app.example.biz", "other.example.biz"},
		"missing name": {"app.example.biz"},
		"other name":   {"x.example.biz", "y.example.biz"},
	}
	for name, csrNames := range cases {
		t.Run(name, func(t *testing.T) {
			h := newHarness(t)
			c := h.register()
			o := h.authorize(c, "app.example.biz", "api.example.biz")
			if name == "extra name" {
				o = h.authorize(c, "app.example.biz")
			}
			csr, _ := newCSR(t, csrNames...)
			_, _, err := c.CreateOrderCert(ctx(t), o.FinalizeURL, csr, true)
			wantProblem(t, err, "badCSR")
			if n := len(h.public.issueCalls()); n != 0 {
				t.Fatalf("Public side must not be called for a bad CSR, got %d", n)
			}
		})
	}
}

func TestFinalizeBeforeReadyIsOrderNotReady(t *testing.T) {
	h := newHarness(t)
	c := h.register()
	o, _ := c.AuthorizeOrder(ctx(t), xacme.DomainIDs("app.example.biz"))
	csr, _ := newCSR(t, "app.example.biz")
	_, _, err := c.CreateOrderCert(ctx(t), o.FinalizeURL, csr, true)
	wantProblem(t, err, "orderNotReady")
}

func TestOtherAccountsCannotReadOrderOrCertificate(t *testing.T) {
	h := newHarness(t)
	owner := h.register()
	o := h.authorize(owner, "app.example.biz")
	csr, _ := newCSR(t, "app.example.biz")
	_, certURL, err := owner.CreateOrderCert(ctx(t), o.FinalizeURL, csr, true)
	if err != nil {
		t.Fatal(err)
	}
	other := h.register()
	_, err = other.FetchCert(ctx(t), certURL, true)
	wantProblem(t, err, "unauthorized")
	_, err = other.GetOrder(ctx(t), o.URI)
	wantProblem(t, err, "unauthorized")
}

func TestStartupMarksProcessingOrdersInvalid(t *testing.T) {
	h := newHarness(t)
	h.public.setBlocking()
	c := h.register()
	o := h.authorize(c, "app.example.biz")
	csr, _ := newCSR(t, "app.example.biz")
	acc, _ := c.GetReg(ctx(t), "")
	if res := h.post(c.Key, acc.URI, o.FinalizeURL, map[string]string{"csr": b64(csr)}); res.Status != http.StatusOK {
		t.Fatalf("finalize: %d %s", res.Status, res.Body)
	}
	<-h.public.started

	h.restart()

	got, err := c.GetOrder(ctx(t), o.URI)
	if err != nil {
		t.Fatal(err)
	}
	if got.Status != xacme.StatusInvalid || got.Error == nil || got.Error.ProblemType != "urn:ietf:params:acme:error:serverInternal" {
		t.Fatalf("expected order left processing to be invalid after restart, got %+v", got)
	}
}
