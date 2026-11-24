package acme_test

import (
	"errors"
	"strings"
	"testing"

	xacme "golang.org/x/crypto/acme"

	"github.com/peschmae/acme-proxy/pkg/acme"
)

func TestIdentifierPolicy(t *testing.T) {
	h := newHarness(t)
	c := h.register()

	cases := []struct {
		name   string
		ids    []xacme.AuthzID
		accept bool
	}{
		{"host in internal domain", xacme.DomainIDs("app.example.biz"), true},
		{"internal domain itself", xacme.DomainIDs("example.biz"), true},
		{"mixed case is normalised", xacme.DomainIDs("App.Example.BIZ"), true},
		{"wildcard under wildcard base", xacme.DomainIDs("*.wild.example.biz"), true},
		{"wildcard base and wildcard together", xacme.DomainIDs("wild.example.biz", "*.wild.example.biz"), true},
		{"name outside internal domain", xacme.DomainIDs("wiki.example.com"), false},
		{"suffix trick", xacme.DomainIDs("evilexample.biz"), false},
		{"wildcard not under a wildcard base", xacme.DomainIDs("*.app.example.biz"), false},
		{"wildcard of the internal domain", xacme.DomainIDs("*.example.biz"), false},
		{"double wildcard", xacme.DomainIDs("*.*.wild.example.biz"), false},
		{"ip identifier", xacme.IPIDs("10.0.0.1"), false},
		{"one bad name rejects the order", xacme.DomainIDs("ok.example.biz", "bad.example.com"), false},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			o, err := c.AuthorizeOrder(ctx(t), tc.ids)
			if tc.accept {
				if err != nil {
					t.Fatalf("expected order to be accepted, got %v", err)
				}
				if o.Status != xacme.StatusPending || len(o.AuthzURLs) != len(tc.ids) {
					t.Fatalf("unexpected order %+v", o)
				}
				return
			}
			wantProblem(t, err, "rejectedIdentifier")
		})
	}
}

func TestRejectedIdentifierListsEachOffendingIdentifier(t *testing.T) {
	h := newHarness(t)
	c := h.register()
	acc, _ := c.GetReg(ctx(t), "")
	res := h.post(c.Key, acc.URI, h.ts.URL+"/acme/new-order", map[string]any{"identifiers": []map[string]string{
		{"type": "dns", "value": "ok.example.biz"},
		{"type": "dns", "value": "a.example.com"},
		{"type": "ip", "value": "10.0.0.1"},
	}})
	body := res.json(t)
	subs, _ := body["subproblems"].([]any)
	if res.Status != 400 || body["type"] != "urn:ietf:params:acme:error:rejectedIdentifier" || len(subs) != 2 {
		t.Fatalf("expected rejectedIdentifier with 2 subproblems, got %d %s", res.Status, res.Body)
	}
}

func TestOnlyHTTP01IsOffered(t *testing.T) {
	h := newHarness(t)
	c := h.register()
	o, err := c.AuthorizeOrder(ctx(t), xacme.DomainIDs("app.example.biz", "*.wild.example.biz"))
	if err != nil {
		t.Fatal(err)
	}
	for _, u := range o.AuthzURLs {
		az, err := c.GetAuthorization(ctx(t), u)
		if err != nil {
			t.Fatal(err)
		}
		http01(t, az)
		if az.Wildcard && az.Identifier.Value != "wild.example.biz" {
			t.Fatalf("wildcard authorization should be for the base name, got %q", az.Identifier.Value)
		}
	}
}

func TestConfigValidation(t *testing.T) {
	ok := acme.Config{InternalDomain: "example.biz", WildcardBases: []string{"wild.example.biz"}, DatabasePath: "x.db"}
	if err := ok.Validate(); err != nil {
		t.Fatalf("valid config rejected: %v", err)
	}
	cases := map[string]func(*acme.Config){
		"missing internal domain":          func(c *acme.Config) { c.InternalDomain = "" },
		"invalid internal domain":          func(c *acme.Config) { c.InternalDomain = "not a domain" },
		"internal domain as wildcard base": func(c *acme.Config) { c.WildcardBases = []string{"Example.biz."} },
		"wildcard base outside domain":     func(c *acme.Config) { c.WildcardBases = []string{"wild.example.com"} },
		"wildcard base suffix trick":       func(c *acme.Config) { c.WildcardBases = []string{"evilexample.biz"} },
		"missing database path":            func(c *acme.Config) { c.DatabasePath = "" },
	}
	for name, mod := range cases {
		t.Run(name, func(t *testing.T) {
			cfg := ok
			cfg.WildcardBases = append([]string(nil), ok.WildcardBases...)
			mod(&cfg)
			if err := cfg.Validate(); err == nil {
				t.Fatal("expected configuration error")
			}
			if _, err := acme.New(cfg, acme.Dependencies{Public: newFakePublic(t)}); err == nil ||
				!strings.Contains(err.Error(), "invalid configuration") {
				t.Fatalf("expected New to refuse to start, got %v", err)
			}
		})
	}
	if _, err := acme.New(ok, acme.Dependencies{}); err == nil || errors.Is(err, nil) {
		t.Fatal("expected New to require a PublicCA")
	}
}
