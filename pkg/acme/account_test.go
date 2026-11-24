package acme_test

import (
	"crypto"
	"errors"
	"net/http"
	"strings"
	"testing"

	xacme "golang.org/x/crypto/acme"

	"github.com/peschmae/acme-proxy/pkg/acme"
)

func TestRegisterInternalAccount(t *testing.T) {
	h := newHarness(t)
	c := h.newClient()

	dir, err := c.Discover(ctx(t))
	if err != nil {
		t.Fatalf("discover: %v", err)
	}
	if !strings.HasSuffix(dir.NonceURL, "/acme/new-nonce") || !strings.HasSuffix(dir.OrderURL, "/acme/new-order") {
		t.Fatalf("unexpected directory: %+v", dir)
	}

	acc, err := c.Register(ctx(t), &xacme.Account{Contact: []string{"mailto:ops@example.biz"}}, xacme.AcceptTOS)
	if err != nil {
		t.Fatalf("register: %v", err)
	}
	if !strings.HasPrefix(acc.URI, h.ts.URL+"/acme/account/") {
		t.Fatalf("account URI %q not under /acme/account/", acc.URI)
	}
	if acc.Status != xacme.StatusValid || acc.Contact[0] != "mailto:ops@example.biz" {
		t.Fatalf("unexpected account %+v", acc)
	}
}

func TestRegisteringTheSameKeyTwiceReturnsTheExistingAccount(t *testing.T) {
	h := newHarness(t)
	c := h.register()
	first, _ := c.GetReg(ctx(t), "")

	res := h.post(c.Key, "", h.ts.URL+"/acme/new-account", map[string]any{"termsOfServiceAgreed": true})
	if res.Status != http.StatusOK || res.Header.Get("Location") != first.URI {
		t.Fatalf("expected 200 with existing location %s, got %d %s", first.URI, res.Status, res.Header.Get("Location"))
	}
}

func TestOnlyReturnExistingFindsAccountByKey(t *testing.T) {
	h := newHarness(t)
	c := h.register()

	// A fresh client with the same key but no cached account URL.
	again := &xacme.Client{Key: c.Key, DirectoryURL: h.directoryURL(), HTTPClient: h.ts.Client()}
	acc, err := again.GetReg(ctx(t), "")
	if err != nil {
		t.Fatalf("GetReg: %v", err)
	}
	if acc.URI == "" || acc.Status != xacme.StatusValid {
		t.Fatalf("unexpected account %+v", acc)
	}

	if _, err := h.newClient().GetReg(ctx(t), ""); !errors.Is(err, xacme.ErrNoAccount) {
		t.Fatalf("expected ErrNoAccount for an unknown key, got %v", err)
	}
}

func TestUnknownKidIsAccountDoesNotExist(t *testing.T) {
	h := newHarness(t)
	c := h.newClient()
	res := h.post(c.Key, h.ts.URL+"/acme/account/doesnotexist", h.ts.URL+"/acme/new-order",
		map[string]any{"identifiers": []map[string]string{{"type": "dns", "value": "a.example.biz"}}})
	if res.Status != http.StatusBadRequest {
		t.Fatalf("expected 400, got %d: %s", res.Status, res.Body)
	}
	if typ := res.json(t)["type"]; typ != "urn:ietf:params:acme:error:accountDoesNotExist" {
		t.Fatalf("expected accountDoesNotExist, got %v", typ)
	}
}

func TestFetchAndUpdateInternalAccount(t *testing.T) {
	h := newHarness(t)
	c := h.register()

	acc, err := c.GetReg(ctx(t), "")
	if err != nil {
		t.Fatal(err)
	}
	res := h.post(c.Key.(crypto.Signer), acc.URI, acc.URI, nil) // POST-as-GET
	if res.Status != http.StatusOK || res.json(t)["status"] != "valid" {
		t.Fatalf("POST-as-GET account: %d %s", res.Status, res.Body)
	}

	acc.Contact = []string{"mailto:new@example.biz"}
	updated, err := c.UpdateReg(ctx(t), acc)
	if err != nil {
		t.Fatalf("update: %v", err)
	}
	if len(updated.Contact) != 1 || updated.Contact[0] != "mailto:new@example.biz" {
		t.Fatalf("contact not updated: %+v", updated.Contact)
	}

	acc.Contact = []string{"tel:+41000000000"}
	_, err = c.UpdateReg(ctx(t), acc)
	wantProblem(t, err, "unsupportedContact")
}

func TestDeactivatedAccountKeyIsRejected(t *testing.T) {
	h := newHarness(t)
	c := h.register()
	if err := c.DeactivateReg(ctx(t)); err != nil {
		t.Fatalf("deactivate: %v", err)
	}
	_, err := c.AuthorizeOrder(ctx(t), xacme.DomainIDs("a.example.biz"))
	wantProblem(t, err, "unauthorized")

	// Registering again with the same key does not revive it.
	res := h.post(c.Key, "", h.ts.URL+"/acme/new-account", map[string]any{"termsOfServiceAgreed": true})
	if res.Status != http.StatusForbidden {
		t.Fatalf("expected 403 for deactivated key, got %d: %s", res.Status, res.Body)
	}
}

func TestAccountOrdersList(t *testing.T) {
	h := newHarness(t)
	c := h.register()
	o, err := c.AuthorizeOrder(ctx(t), xacme.DomainIDs("a.example.biz"))
	if err != nil {
		t.Fatal(err)
	}
	acc, _ := c.GetReg(ctx(t), "")

	res := h.post(c.Key, acc.URI, acc.OrdersURL, nil)
	if res.Status != http.StatusOK {
		t.Fatalf("orders list: %d %s", res.Status, res.Body)
	}
	orders, _ := res.json(t)["orders"].([]any)
	if len(orders) != 1 || orders[0] != o.URI {
		t.Fatalf("expected [%s], got %v", o.URI, orders)
	}

	// Another account cannot read it.
	other := h.register()
	otherAcc, _ := other.GetReg(ctx(t), "")
	if res := h.post(other.Key, otherAcc.URI, acc.OrdersURL, nil); res.Status != http.StatusForbidden {
		t.Fatalf("expected 403 for foreign orders list, got %d", res.Status)
	}
}

func TestNewAccountRejectsNonMailtoContacts(t *testing.T) {
	h := newHarness(t)
	_, err := h.newClient().Register(ctx(t), &xacme.Account{Contact: []string{"tel:+41000000000"}}, xacme.AcceptTOS)
	wantProblem(t, err, "unsupportedContact")
}

func TestKeyChangeIsUnsupported(t *testing.T) {
	h := newHarness(t)
	c := h.register()
	err := c.AccountKeyRollover(ctx(t), h.newClient().Key)
	wantProblem(t, err, "malformed")
	var e *xacme.Error
	if errors.As(err, &e) && e.StatusCode != http.StatusNotImplemented {
		t.Fatalf("expected 501, got %d", e.StatusCode)
	}
}

var _ = acme.PathPrefix
