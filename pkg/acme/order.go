package acme

import (
	"context"
	"crypto"
	"crypto/x509"
	"encoding/base64"
	"encoding/json"
	"encoding/pem"
	"errors"
	"fmt"
	"net/http"
	"sort"
	"strings"
	"time"

	"github.com/go-chi/chi/v5"
)

type orderResponse struct {
	Status         Status       `json:"status"`
	Expires        string       `json:"expires"`
	Identifiers    []Identifier `json:"identifiers"`
	Authorizations []string     `json:"authorizations"`
	Finalize       string       `json:"finalize"`
	Certificate    string       `json:"certificate,omitempty"`
	Error          *Problem     `json:"error,omitempty"`
}

func renderOrder(r *http.Request, o *Order) orderResponse {
	resp := orderResponse{
		Status:      o.Status,
		Expires:     o.ExpiresAt.UTC().Format(time.RFC3339),
		Identifiers: o.Identifiers,
		Finalize:    linkURL(r, "order", o.ID, "finalize"),
		Error:       o.Error,
	}
	for _, id := range o.AuthorizationIDs {
		resp.Authorizations = append(resp.Authorizations, linkURL(r, "authorization", id))
	}
	if o.Status == StatusValid && o.CertificateID != "" {
		resp.Certificate = linkURL(r, "certificate", o.CertificateID)
	}
	return resp
}

// processingRetryAfter is the polling hint given while an order is processing.
const processingRetryAfter = "1"

func writeOrder(w http.ResponseWriter, r *http.Request, status int, o *Order) {
	w.Header().Set("Location", linkURL(r, "order", o.ID))
	if o.Status == StatusProcessing {
		w.Header().Set("Retry-After", processingRetryAfter)
	}
	writeJSON(w, status, renderOrder(r, o))
}

// newOrder implements RFC 8555 §7.4 with acme-proxy's Identifier policy.
// Every Internal Order gets fresh Internal Authorizations.
func (s *Server) newOrder(w http.ResponseWriter, r *http.Request) {
	acc := accountFrom(r)
	var req struct {
		Identifiers []Identifier `json:"identifiers"`
		NotBefore   string       `json:"notBefore"`
		NotAfter    string       `json:"notAfter"`
	}
	if err := json.Unmarshal(payloadFrom(r).value, &req); err != nil {
		writeProblem(w, malformed("malformed JSON in request body"))
		return
	}
	if req.NotBefore != "" || req.NotAfter != "" {
		writeProblem(w, malformed("notBefore and notAfter are not supported; the Public CA decides the validity period"))
		return
	}
	ids, err := s.checkIdentifiers(req.Identifiers)
	if err != nil {
		writeProblem(w, err)
		return
	}

	now := time.Now()
	o := &Order{
		AccountID:   acc.ID,
		Status:      StatusPending,
		Identifiers: ids,
		ExpiresAt:   now.Add(s.cfg.OrderLifetime),
		CreatedAt:   now,
	}

	s.mu.Lock()
	defer s.mu.Unlock()
	if err := s.store.CreateOrder(o); err != nil {
		writeProblem(w, serverInternal("error creating order"))
		return
	}
	for _, id := range ids {
		az, err := s.newAuthorization(acc, o.ID, id, o.ExpiresAt)
		if err != nil {
			writeProblem(w, serverInternal("error creating authorization"))
			return
		}
		o.AuthorizationIDs = append(o.AuthorizationIDs, az.ID)
	}
	if err := s.store.UpdateOrder(o); err != nil {
		writeProblem(w, serverInternal("error creating order"))
		return
	}
	s.log.Info("internal order created", "account", acc.ID, "order", o.ID, "identifiers", identifierValues(ids))
	writeOrder(w, r, http.StatusCreated, o)
}

func identifierValues(ids []Identifier) []string {
	out := make([]string, len(ids))
	for i, id := range ids {
		out[i] = id.Value
	}
	return out
}

// refreshOrder applies expiry and authorization results to a pending or
// ready order and persists any change. Callers hold s.mu.
func (s *Server) refreshOrder(o *Order) (*Order, error) {
	if o.Status != StatusPending && o.Status != StatusReady {
		return o, nil
	}
	if time.Now().After(o.ExpiresAt) {
		o.Status = StatusInvalid
		o.Error = unauthorized("order expired before it was finalized")
		return o, s.store.UpdateOrder(o)
	}
	if o.Status == StatusReady {
		return o, nil
	}

	allValid := true
	for _, id := range o.AuthorizationIDs {
		az, err := s.store.GetAuthorization(id)
		if err != nil {
			return nil, err
		}
		chs, err := s.refreshAuthorization(az)
		if err != nil {
			return nil, err
		}
		switch az.Status {
		case StatusValid:
		case StatusPending:
			allValid = false
		default: // invalid, deactivated, expired
			o.Status = StatusInvalid
			o.Error = unauthorized("authorization for %s is %s", az.Identifier.Value, az.Status)
			for _, ch := range chs {
				if ch.Error != nil {
					sub := *ch.Error
					sub.Identifier = &Identifier{Type: IdentifierDNS, Value: az.Identifier.Value}
					o.Error.Subproblems = append(o.Error.Subproblems, &sub)
				}
			}
			return o, s.store.UpdateOrder(o)
		}
	}
	if allValid {
		o.Status = StatusReady
		return o, s.store.UpdateOrder(o)
	}
	return o, nil
}

func (s *Server) loadOwnedOrder(acc *Account, id string) (*Order, error) {
	o, err := s.store.GetOrder(id)
	if errors.Is(err, ErrNotFound) {
		return nil, notFound("order not found")
	}
	if err != nil {
		return nil, serverInternal("error loading order")
	}
	if o.AccountID != acc.ID {
		return nil, unauthorized("account does not own this order")
	}
	return o, nil
}

func (s *Server) getOrder(w http.ResponseWriter, r *http.Request) {
	s.mu.Lock()
	defer s.mu.Unlock()
	o, err := s.loadOwnedOrder(accountFrom(r), chi.URLParam(r, "orderID"))
	if err != nil {
		writeProblem(w, err)
		return
	}
	if o, err = s.refreshOrder(o); err != nil {
		writeProblem(w, serverInternal("error refreshing order"))
		return
	}
	writeOrder(w, r, http.StatusOK, o)
}

// finalizeOrder checks the CSR, moves the Internal Order to processing and
// hands the CSR, unchanged, to the Public side (ADR-0001).
func (s *Server) finalizeOrder(w http.ResponseWriter, r *http.Request) {
	acc := accountFrom(r)
	var req struct {
		CSR string `json:"csr"`
	}
	if err := json.Unmarshal(payloadFrom(r).value, &req); err != nil {
		writeProblem(w, malformed("malformed JSON in request body"))
		return
	}

	s.mu.Lock()
	defer s.mu.Unlock()
	o, err := s.loadOwnedOrder(acc, chi.URLParam(r, "orderID"))
	if err != nil {
		writeProblem(w, err)
		return
	}
	if o, err = s.refreshOrder(o); err != nil {
		writeProblem(w, serverInternal("error refreshing order"))
		return
	}
	if o.Status != StatusReady {
		writeProblem(w, NewProblem(http.StatusForbidden, "orderNotReady", "order is %s, not ready", o.Status))
		return
	}

	// RFC 8555 is ambiguous about padding; accept padded base64url too.
	csrDER, err := base64.RawURLEncoding.DecodeString(strings.TrimRight(req.CSR, "="))
	if err != nil {
		writeProblem(w, NewProblem(http.StatusBadRequest, "badCSR", "error base64url-decoding csr"))
		return
	}
	csr, err := x509.ParseCertificateRequest(csrDER)
	if err != nil {
		writeProblem(w, NewProblem(http.StatusBadRequest, "badCSR", "unable to parse csr: %v", err))
		return
	}
	if err := csr.CheckSignature(); err != nil {
		writeProblem(w, NewProblem(http.StatusBadRequest, "badCSR", "csr signature check failed"))
		return
	}
	if err := matchCSR(csr, o.Identifiers); err != nil {
		writeProblem(w, err)
		return
	}

	o.CSR = csrDER
	o.Status = StatusProcessing
	if err := s.store.UpdateOrder(o); err != nil {
		writeProblem(w, serverInternal("error updating order"))
		return
	}
	s.log.Info("internal order finalized; starting public order", "account", acc.ID, "order", o.ID)

	s.bg.Add(1)
	go s.issue(o.ID, csrDER, o.Identifiers)

	writeOrder(w, r, http.StatusOK, o)
}

// matchCSR requires the CSR to request exactly the order's identifiers
// (subject common name included) and nothing else.
func matchCSR(csr *x509.CertificateRequest, ids []Identifier) error {
	if len(csr.IPAddresses) > 0 || len(csr.EmailAddresses) > 0 || len(csr.URIs) > 0 {
		return NewProblem(http.StatusBadRequest, "badCSR", "csr may only contain DNS names")
	}
	names := map[string]bool{}
	for _, n := range csr.DNSNames {
		names[normalizeName(n)] = true
	}
	if cn := csr.Subject.CommonName; cn != "" {
		names[normalizeName(cn)] = true
	}
	got := make([]string, 0, len(names))
	for n := range names {
		got = append(got, n)
	}
	want := identifierValues(ids)
	sort.Strings(got)
	sort.Strings(want)
	if strings.Join(got, ",") != strings.Join(want, ",") {
		return NewProblem(http.StatusBadRequest, "badCSR",
			"csr names %v do not match order identifiers %v exactly", got, want)
	}
	return nil
}

// issue runs one Public Order for a finalized Internal Order and records the
// outcome. Failures are passed through and never retried.
func (s *Server) issue(orderID string, csrDER []byte, ids []Identifier) {
	defer s.bg.Done()
	ctx, cancel := context.WithTimeout(context.WithValue(s.bgCtx, orderIDKey{}, orderID), s.cfg.PublicOrderTimeout)
	defer cancel()

	chainPEM, issueErr := s.public.Issue(ctx, csrDER, ids)
	if s.bgCtx.Err() != nil {
		// Shutting down: the order stays processing and is marked invalid
		// by recoverProcessingOrders on the next start.
		return
	}

	s.mu.Lock()
	defer s.mu.Unlock()
	o, err := s.store.GetOrder(orderID)
	if err != nil || o.Status != StatusProcessing {
		s.log.Error("public order finished for an order that is no longer processing", "order", orderID, "error", err)
		return
	}

	var cert *Certificate
	if issueErr == nil {
		cert, issueErr = s.storeCertificate(o, csrDER, chainPEM)
	}
	if issueErr != nil {
		o.Status = StatusInvalid
		o.Error = asProblem(issueErr)
		s.log.Warn("public order failed", "account", o.AccountID, "order", o.ID, "error", issueErr)
	} else {
		o.Status = StatusValid
		o.CertificateID = cert.ID
		s.log.Info("certificate issued", "account", o.AccountID, "order", o.ID, "certificate", cert.ID, "serial", cert.Serial)
	}
	if err := s.store.UpdateOrder(o); err != nil {
		s.log.Error("error updating order after public order", "order", o.ID, "error", err)
	}
}

func (s *Server) storeCertificate(o *Order, csrDER, chainPEM []byte) (*Certificate, error) {
	block, _ := pem.Decode(chainPEM)
	if block == nil || block.Type != "CERTIFICATE" {
		return nil, serverInternal("the Public CA returned no PEM certificate")
	}
	leaf, err := x509.ParseCertificate(block.Bytes)
	if err != nil {
		return nil, serverInternal("the Public CA returned an unparsable certificate: %v", err)
	}
	csr, err := x509.ParseCertificateRequest(csrDER)
	if err != nil {
		return nil, serverInternal("stored csr is unparsable")
	}
	if !publicKeysEqual(leaf.PublicKey, csr.PublicKey) {
		return nil, serverInternal("the Public CA returned a certificate for a different key than the csr")
	}
	cert := &Certificate{
		AccountID: o.AccountID,
		OrderID:   o.ID,
		Serial:    fmt.Sprintf("%x", leaf.SerialNumber),
		ChainPEM:  chainPEM,
		CreatedAt: time.Now(),
	}
	if err := s.store.CreateCertificate(cert); err != nil {
		return nil, serverInternal("error storing certificate")
	}
	return cert, nil
}

type equalKey interface{ Equal(crypto.PublicKey) bool }

func publicKeysEqual(a, b any) bool {
	k, ok := a.(equalKey)
	return ok && k.Equal(b)
}

// recoverProcessingOrders marks orders left processing by a previous run as
// invalid, so Requesters stop polling and start over.
func (s *Server) recoverProcessingOrders() error {
	orders, err := s.store.GetOrdersByStatus(StatusProcessing)
	if err != nil {
		return fmt.Errorf("loading processing orders: %w", err)
	}
	for _, o := range orders {
		o.Status = StatusInvalid
		o.Error = serverInternal("acme-proxy restarted while the Public Order was in progress; place a new order")
		if err := s.store.UpdateOrder(o); err != nil {
			return err
		}
		s.log.Warn("marked order left processing at startup as invalid", "order", o.ID)
	}
	return nil
}
