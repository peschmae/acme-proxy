package public

import (
	"errors"
	"fmt"
	"path/filepath"
	"testing"

	legoacme "github.com/go-acme/lego/v4/acme"

	"github.com/peschmae/acme-proxy/pkg/acme"
)

func TestPublicCAProblemsArePassedThrough(t *testing.T) {
	pd := &legoacme.ProblemDetails{
		Type:       "urn:ietf:params:acme:error:rateLimited",
		Detail:     "too many certificates",
		HTTPStatus: 429,
		SubProblems: []legoacme.SubProblem{{
			Type: "urn:ietf:params:acme:error:dns", Detail: "nxdomain",
			Identifier: legoacme.Identifier{Type: "dns", Value: "a.example.biz"},
		}},
	}
	// lego wraps problems in its own error chains.
	err := toProblem(fmt.Errorf("error: one or more domains had a problem:\n%w", errors.Join(fmt.Errorf("a.example.biz: %w", pd))))
	var p *acme.Problem
	if !errors.As(err, &p) {
		t.Fatalf("expected *acme.Problem, got %T", err)
	}
	if p.Type != pd.Type || p.Detail != pd.Detail || p.Status != 429 || len(p.Subproblems) != 1 || p.Subproblems[0].Identifier.Value != "a.example.biz" {
		t.Fatalf("problem not passed through: %+v", p)
	}

	err = toProblem(errors.New("time limit exceeded waiting for DNS propagation"))
	if !errors.As(err, &p) || p.Type != "urn:ietf:params:acme:error:serverInternal" {
		t.Fatalf("expected serverInternal for non-ACME failures, got %+v", err)
	}
}

func TestPublicAccountIsPersistedPerDirectory(t *testing.T) {
	dir := t.TempDir()
	cfg := Config{DirectoryURL: "https://acme-staging-v02.api.letsencrypt.org/directory", Contact: "ops@example.biz", StateDir: dir}

	first, err := loadOrCreateUser(cfg)
	if err != nil {
		t.Fatal(err)
	}
	again, err := loadOrCreateUser(cfg)
	if err != nil {
		t.Fatal(err)
	}
	if first.KeyPEM != again.KeyPEM {
		t.Fatal("Public Account key was not reused")
	}

	cfg.DirectoryURL = "https://acme-v02.api.letsencrypt.org/directory"
	prod, err := loadOrCreateUser(cfg)
	if err != nil {
		t.Fatal(err)
	}
	if prod.KeyPEM == first.KeyPEM || filepath.Dir(prod.path) != dir || prod.path == first.path {
		t.Fatal("each Public CA directory must get its own account file")
	}
}

func TestUnsupportedDNSProviderIsReported(t *testing.T) {
	if _, err := newDNSProvider("no-such-provider"); err == nil {
		t.Fatal("expected an error")
	}
	if len(SupportedDNSProviders()) == 0 {
		t.Fatal("no DNS providers registered")
	}
}
