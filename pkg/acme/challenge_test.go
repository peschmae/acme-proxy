package acme_test

import (
	"errors"
	"net/http"
	"testing"
	"time"

	xacme "golang.org/x/crypto/acme"

	"github.com/peschmae/acme-proxy/pkg/acme"
)

func TestInternalChallengeSucceedsWithCorrectKeyAuthorization(t *testing.T) {
	h := newHarness(t)
	c := h.register()
	o := h.authorize(c, "app.example.biz")
	if o.Status != xacme.StatusReady {
		t.Fatalf("expected ready order, got %s", o.Status)
	}
	if got := h.hosts.dialedAddrs(); len(got) == 0 || got[0] != "app.example.biz:80" {
		t.Fatalf("expected acme-proxy to dial app.example.biz:80, dialed %v", got)
	}
}

// failChallenge starts an order for name, lets setup prepare the host, and
// asks acme-proxy to check the challenge.
func failChallenge(t *testing.T, h *harness, c *xacme.Client, name string, setup func(token, keyAuth string)) (*xacme.Order, *xacme.Challenge) {
	t.Helper()
	o, err := c.AuthorizeOrder(ctx(t), xacme.DomainIDs(name))
	if err != nil {
		t.Fatal(err)
	}
	az, err := c.GetAuthorization(ctx(t), o.AuthzURLs[0])
	if err != nil {
		t.Fatal(err)
	}
	ch := http01(t, az)
	keyAuth, _ := c.HTTP01ChallengeResponse(ch.Token)
	setup(ch.Token, keyAuth)
	ch, err = c.Accept(ctx(t), ch)
	if err != nil {
		t.Fatalf("accept: %v", err)
	}
	return o, ch
}

func TestInternalChallengeFailures(t *testing.T) {
	cases := []struct {
		name    string
		setup   func(h *harness, host, token, keyAuth string)
		problem string
	}{
		{"wrong key authorization", func(h *harness, host, token, _ string) {
			h.hosts.serve(host, token, token+".not-the-thumbprint")
		}, "incorrectResponse"},
		{"token not served", func(h *harness, host, _, _ string) {
			h.hosts.exists(host)
		}, "unauthorized"},
		{"name does not resolve", func(*harness, string, string, string) {}, "dns"},
		{"connection refused", func(h *harness, host, _, _ string) {
			h.hosts.refuseConnections(host)
		}, "connection"},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			h := newHarness(t)
			c := h.register()
			host := "app.example.biz"
			o, ch := failChallenge(t, h, c, host, func(token, keyAuth string) { tc.setup(h, host, token, keyAuth) })

			if ch.Status != xacme.StatusInvalid || ch.Error == nil {
				t.Fatalf("expected invalid challenge with error, got %+v", ch)
			}
			var e *xacme.Error
			if !errors.As(ch.Error, &e) || e.ProblemType != "urn:ietf:params:acme:error:"+tc.problem {
				t.Fatalf("expected %s, got %v", tc.problem, ch.Error)
			}

			az, err := c.GetAuthorization(ctx(t), o.AuthzURLs[0])
			if err != nil || az.Status != xacme.StatusInvalid {
				t.Fatalf("expected invalid authorization, got %+v %v", az, err)
			}
			if _, err := c.WaitOrder(ctx(t), o.URI); err == nil {
				t.Fatal("expected the order to become invalid")
			}
			if n := len(h.public.issueCalls()); n != 0 {
				t.Fatalf("Public side must not be called, got %d calls", n)
			}
		})
	}
}

func TestWildcardIsValidatedAgainstWildcardBaseHost(t *testing.T) {
	h := newHarness(t)
	c := h.register()
	o := h.authorize(c, "*.wild.example.biz")
	if o.Status != xacme.StatusReady {
		t.Fatalf("expected ready, got %s", o.Status)
	}
	for _, a := range h.hosts.dialedAddrs() {
		if a != "wild.example.biz:80" {
			t.Fatalf("expected only the wildcard base host to be fetched, dialed %s", a)
		}
	}
}

func TestEveryOrderGetsFreshAuthorizations(t *testing.T) {
	h := newHarness(t)
	c := h.register()
	first := h.authorize(c, "app.example.biz")
	second, err := c.AuthorizeOrder(ctx(t), xacme.DomainIDs("app.example.biz"))
	if err != nil {
		t.Fatal(err)
	}
	if second.AuthzURLs[0] == first.AuthzURLs[0] {
		t.Fatal("authorization was reused across orders")
	}
	if second.Status != xacme.StatusPending {
		t.Fatalf("second order should need a fresh Internal Challenge, got %s", second.Status)
	}
}

func TestOrdersAndAuthorizationsExpire(t *testing.T) {
	h := newHarness(t, func(c *acme.Config) { c.OrderLifetime = 300 * time.Millisecond })
	c := h.register()
	o, err := c.AuthorizeOrder(ctx(t), xacme.DomainIDs("app.example.biz"))
	if err != nil {
		t.Fatal(err)
	}
	time.Sleep(500 * time.Millisecond)
	got, err := c.GetOrder(ctx(t), o.URI)
	if err != nil {
		t.Fatal(err)
	}
	if got.Status != xacme.StatusInvalid {
		t.Fatalf("expected expired order to be invalid, got %s", got.Status)
	}
	az, _ := c.GetAuthorization(ctx(t), o.AuthzURLs[0])
	if az.Status != xacme.StatusInvalid {
		t.Fatalf("expected expired authorization to be invalid, got %s", az.Status)
	}
}

func TestOtherAccountsCannotUseAuthorizationsOrChallenges(t *testing.T) {
	h := newHarness(t)
	owner := h.register()
	o, _ := owner.AuthorizeOrder(ctx(t), xacme.DomainIDs("app.example.biz"))
	az, _ := owner.GetAuthorization(ctx(t), o.AuthzURLs[0])

	other := h.register()
	_, err := other.GetAuthorization(ctx(t), o.AuthzURLs[0])
	wantProblem(t, err, "unauthorized")
	_, err = other.Accept(ctx(t), az.Challenges[0])
	wantProblem(t, err, "unauthorized")
	_, err = other.GetOrder(ctx(t), o.URI)
	wantProblem(t, err, "unauthorized")
}

func TestAuthorizationURLsAreConsistent(t *testing.T) {
	h := newHarness(t)
	c := h.register()
	o, _ := c.AuthorizeOrder(ctx(t), xacme.DomainIDs("app.example.biz"))
	acc, _ := c.GetReg(ctx(t), "")
	res := h.post(c.Key, acc.URI, o.AuthzURLs[0], nil)
	if res.Status != http.StatusOK || res.Header.Get("Location") != o.AuthzURLs[0] {
		t.Fatalf("authorization Location %q differs from order link %q", res.Header.Get("Location"), o.AuthzURLs[0])
	}
	challenges, _ := res.json(t)["challenges"].([]any)
	chURL := challenges[0].(map[string]any)["url"].(string)
	res = h.post(c.Key, acc.URI, chURL, nil)
	if want := `<` + o.AuthzURLs[0] + `>;rel="up"`; !containsHeader(res.Header["Link"], want) {
		t.Fatalf("challenge Link up %v does not point at %s", res.Header["Link"], o.AuthzURLs[0])
	}
}

func containsHeader(vals []string, want string) bool {
	for _, v := range vals {
		if v == want {
			return true
		}
	}
	return false
}
