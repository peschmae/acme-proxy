package acme_test

import (
	"bytes"
	"encoding/base64"
	"testing"

	xacme "golang.org/x/crypto/acme"
)

func b64(b []byte) string { return base64.RawURLEncoding.EncodeToString(b) }

func TestOwnerRevokesThroughPublicAccount(t *testing.T) {
	h := newHarness(t)
	c := h.register()
	chain, _ := h.obtain(c, "app.example.biz")

	if err := c.RevokeCert(ctx(t), nil, chain[0], xacme.CRLReasonKeyCompromise); err != nil {
		t.Fatalf("revoke: %v", err)
	}
	calls := h.public.revokeCalls()
	if len(calls) != 1 || !bytes.Equal(calls[0].Cert, chain[0]) || calls[0].Reason != int(xacme.CRLReasonKeyCompromise) {
		t.Fatalf("expected revocation forwarded to the Public side, got %+v", calls)
	}

	// A second revocation answers alreadyRevoked (which the client treats as
	// success) and is not forwarded again.
	acc, _ := c.GetReg(ctx(t), "")
	res := h.post(c.Key, acc.URI, h.ts.URL+"/acme/revoke-cert", map[string]any{"certificate": b64(chain[0])})
	if res.Status != 400 || res.json(t)["type"] != "urn:ietf:params:acme:error:alreadyRevoked" {
		t.Fatalf("expected alreadyRevoked, got %d %s", res.Status, res.Body)
	}
	if n := len(h.public.revokeCalls()); n != 1 {
		t.Fatalf("expected one forwarded revocation, got %d", n)
	}
}

func TestOtherAccountCannotRevoke(t *testing.T) {
	h := newHarness(t)
	owner := h.register()
	chain, _ := h.obtain(owner, "app.example.biz")

	other := h.register()
	err := other.RevokeCert(ctx(t), nil, chain[0], xacme.CRLReasonUnspecified)
	wantProblem(t, err, "unauthorized")
	if n := len(h.public.revokeCalls()); n != 0 {
		t.Fatalf("revocation must not be forwarded, got %d", n)
	}
}

func TestRevocationWithCertificateKeyIsRefused(t *testing.T) {
	h := newHarness(t)
	c := h.register()
	chain, certKey := h.obtain(c, "app.example.biz")

	err := c.RevokeCert(ctx(t), certKey, chain[0], xacme.CRLReasonUnspecified)
	wantProblem(t, err, "unauthorized")
	if n := len(h.public.revokeCalls()); n != 0 {
		t.Fatalf("revocation must not be forwarded, got %d", n)
	}
}

func TestRevokingUnknownCertificateIsRefused(t *testing.T) {
	h := newHarness(t)
	c := h.register()
	chain, _ := h.obtain(c, "app.example.biz")
	// A certificate acme-proxy never issued: the fake CA's own certificate.
	err := c.RevokeCert(ctx(t), nil, h.public.ca.der, xacme.CRLReasonUnspecified)
	wantProblem(t, err, "unauthorized")
	_ = chain
}
