package acme

import (
	"bytes"
	"context"
	"crypto/x509"
	"encoding/base64"
	"encoding/json"
	"encoding/pem"
	"errors"
	"fmt"
	"net/http"
	"time"

	"github.com/go-chi/chi/v5"
)

// certificate serves the chain to the Internal Account that ordered it.
func (s *Server) certificate(w http.ResponseWriter, r *http.Request) {
	acc := accountFrom(r)
	c, err := s.store.GetCertificate(chi.URLParam(r, "certID"))
	if errors.Is(err, ErrNotFound) {
		writeProblem(w, notFound("certificate not found"))
		return
	}
	if err != nil {
		writeProblem(w, serverInternal("error loading certificate"))
		return
	}
	if c.AccountID != acc.ID {
		writeProblem(w, unauthorized("account does not own this certificate"))
		return
	}
	w.Header().Set("Content-Type", "application/pem-certificate-chain")
	w.WriteHeader(http.StatusOK)
	_, _ = w.Write(c.ChainPEM)
}

// revokeCert implements RFC 8555 §7.6 for the Internal Account that ordered
// the certificate. The revocation is forwarded through the Public Account.
func (s *Server) revokeCert(w http.ResponseWriter, r *http.Request) {
	if jwsFrom(r).Signatures[0].Protected.KeyID == "" {
		writeProblem(w, unauthorized("revocation must be signed by the Internal Account that ordered the certificate; revocation with the certificate key is not supported"))
		return
	}
	acc := accountFrom(r)

	var req struct {
		Certificate string `json:"certificate"`
		Reason      *int   `json:"reason"`
	}
	if err := json.Unmarshal(payloadFrom(r).value, &req); err != nil {
		writeProblem(w, malformed("malformed JSON in request body"))
		return
	}
	der, err := base64.RawURLEncoding.DecodeString(req.Certificate)
	if err != nil {
		writeProblem(w, malformed("error base64url-decoding certificate"))
		return
	}
	leaf, err := x509.ParseCertificate(der)
	if err != nil {
		writeProblem(w, malformed("unable to parse certificate"))
		return
	}
	reason := 0
	if req.Reason != nil {
		reason = *req.Reason
	}
	if reason < 0 || reason > 10 || reason == 7 {
		writeProblem(w, NewProblem(http.StatusBadRequest, "badRevocationReason", "unsupported revocation reason %d", reason))
		return
	}

	s.mu.Lock()
	c, err := s.store.GetCertificateBySerial(fmt.Sprintf("%x", leaf.SerialNumber))
	if err != nil || !leafMatches(c.ChainPEM, der) {
		s.mu.Unlock()
		writeProblem(w, unauthorized("certificate was not issued through acme-proxy"))
		return
	}
	if c.AccountID != acc.ID {
		s.mu.Unlock()
		writeProblem(w, unauthorized("only the Internal Account that ordered a certificate may revoke it"))
		return
	}
	if c.Revoked {
		s.mu.Unlock()
		writeProblem(w, NewProblem(http.StatusBadRequest, "alreadyRevoked", "certificate is already revoked"))
		return
	}
	s.mu.Unlock()

	ctx, cancel := context.WithTimeout(r.Context(), time.Minute)
	defer cancel()
	if err := s.public.Revoke(ctx, der, reason); err != nil {
		s.log.Warn("public revocation failed", "account", acc.ID, "certificate", c.ID, "error", err)
		writeProblem(w, err)
		return
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	if c, err = s.store.GetCertificate(c.ID); err == nil {
		c.Revoked = true
		err = s.store.UpdateCertificate(c)
	}
	if err != nil {
		writeProblem(w, serverInternal("certificate revoked publicly but storing that failed"))
		return
	}
	s.log.Info("certificate revoked", "account", acc.ID, "certificate", c.ID, "serial", c.Serial, "reason", reason)
	w.WriteHeader(http.StatusOK)
}

func leafMatches(chainPEM, der []byte) bool {
	block, _ := pem.Decode(chainPEM)
	return block != nil && bytes.Equal(block.Bytes, der)
}
