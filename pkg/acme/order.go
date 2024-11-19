package acme

import (
	"context"
	"crypto/subtle"
	"crypto/x509"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"net/http"
	"net/url"
	"sort"
	"strings"
	"time"

	"github.com/go-chi/chi/v5"
	"go.step.sm/crypto/keyutil"
	"go.step.sm/crypto/x509util"
)

type IdentifierType string

const (
	// IP is the ACME ip identifier type
	IP IdentifierType = "ip"
	// DNS is the ACME dns identifier type
	DNS IdentifierType = "dns"
)

// Identifier encodes the type that an order pertains to.
type Identifier struct {
	Type  IdentifierType `json:"type"`
	Value string         `json:"value"`
}

var MinRSAKeyBytes = 256
var defaultOrderExpiry = time.Hour * 24
var defaultOrderBackdate = time.Minute

var defaultTLSCertDuration = time.Hour * 24 * 90

// NewOrderRequest represents the body for a NewOrder request.
type NewOrderRequest struct {
	Identifiers []Identifier `json:"identifiers"`
	NotBefore   time.Time    `json:"notBefore,omitempty"`
	NotAfter    time.Time    `json:"notAfter,omitempty"`
}

func trimIfWildcard(value string) (string, bool) {
	if strings.HasPrefix(value, "*.") {
		return strings.TrimPrefix(value, "*."), true
	}
	return value, false
}

// FinalizeRequest captures the body for a Finalize order request.
type FinalizeRequest struct {
	CSR string `json:"csr"`
	csr *x509.CertificateRequest
}

// Validate validates a finalize request body.
func (f *FinalizeRequest) Validate() error {
	var err error
	// RFC 8555 isn't 100% conclusive about using raw base64-url encoding for the
	// CSR specifically, instead of "normal" base64-url encoding (incl. padding).
	// By trimming the padding from CSRs submitted by ACME clients that use
	// base64-url encoding instead of raw base64-url encoding, these are also
	// supported. This was reported in https://github.com/smallstep/certificates/issues/939
	// to be the case for a Synology DSM NAS system.
	csrBytes, err := base64.RawURLEncoding.DecodeString(strings.TrimRight(f.CSR, "="))
	if err != nil {
		return AcmeError{http.StatusBadRequest, "malformed", "error base64url decoding csr"}
	}
	f.csr, err = x509.ParseCertificateRequest(csrBytes)
	if err != nil {
		return AcmeError{http.StatusBadRequest, "malformed", "unable to parse csr"}
	}
	if err = f.csr.CheckSignature(); err != nil {
		return AcmeError{http.StatusBadRequest, "malformed", "csr failed signature check"}
	}
	return nil
}

// Validate validates a new-order request body.
func (n *NewOrderRequest) Validate() error {
	if len(n.Identifiers) == 0 {
		return AcmeError{http.StatusBadRequest, "malformed", "identifiers list cannot be empty"}
	}
	for _, id := range n.Identifiers {
		switch id.Type {
		case DNS:
			value, _ := trimIfWildcard(id.Value)
			if _, err := x509util.SanitizeName(value); err != nil {
				return AcmeError{http.StatusBadRequest, "malformed", fmt.Sprintf("invalid DNS name: %s", id.Value)}
			}
		default:
			return AcmeError{http.StatusBadRequest, "malformed", fmt.Sprintf("identifier type unsupported: %s", id.Type)}
		}
	}

	// TODO(hs): add some validations for DNS domains?
	// TODO(hs): combine the errors from this with allow/deny policy, like example error in https://datatracker.ietf.org/doc/html/rfc8555#section-6.7.1

	return nil
}

func newOrder(w http.ResponseWriter, r *http.Request) {
	ctx := r.Context()
	db := ctx.Value(dbKey{}).(Database)
	baseURL := r.Context().Value(baseUrlKey{}).(*url.URL).String()

	acc := ctx.Value(accContextKey{}).(*Account)
	if acc == nil {
		AcmeError{http.StatusUnauthorized, "unauthorized", "account not found"}.Write(w)
		return
	}

	payload := payloadFromContext(ctx)

	var nor NewOrderRequest
	if err := json.Unmarshal(payload.Value, &nor); err != nil {
		AcmeError{http.StatusBadRequest, "malformed", "error unmarshaling newOrder request"}.Write(w)
		return
	}

	if err := nor.Validate(); err != nil {
		AcmeError{http.StatusBadRequest, "malformed", err.Error()}.Write(w)
		return
	}

	now := time.Now()
	// New order.
	o := &Order{
		AccountID:        acc.ID,
		Status:           StatusPending,
		Identifiers:      nor.Identifiers,
		ExpiresAt:        now.Add(defaultOrderExpiry),
		AuthorizationIDs: make([]string, len(nor.Identifiers)),
		NotBefore:        nor.NotBefore,
		NotAfter:         nor.NotAfter,
	}

	for i, identifier := range o.Identifiers {
		az := &Authorization{
			AccountID:  acc.ID,
			Identifier: identifier,
			ExpiresAt:  o.ExpiresAt,
			Status:     StatusPending,
		}
		if err := newAuthorization(ctx, az); err != nil {
			AcmeError{http.StatusInternalServerError, "serverInternal", "error creating authorization"}.Write(w)
			return
		}
		o.AuthorizationIDs[i] = az.ID
	}

	if o.NotBefore.IsZero() {
		o.NotBefore = now
	}
	if o.NotAfter.IsZero() {
		o.NotAfter = o.NotBefore.Add(defaultTLSCertDuration)
	}
	// If request NotBefore was empty then backdate the order.NotBefore (now)
	// to avoid timing issues.
	if nor.NotBefore.IsZero() {
		o.NotBefore = o.NotBefore.Add(-defaultOrderBackdate)
	}

	if err := db.CreateOrder(o); err != nil {
		AcmeError{http.StatusInternalServerError, "serverInternal", "error creating order"}.Write(w)
		return
	}

	// Add links for authorizations and finzliation
	o.AuthorizationURLs = make([]string, len(o.AuthorizationIDs))
	for i, azID := range o.AuthorizationIDs {
		o.AuthorizationURLs[i] = baseURL + "authorization/" + azID
	}
	if o.CertificateID != "" {
		o.CertificateURL = baseURL + "cert/" + o.CertificateID
	}

	o.FinalizeURL = baseURL + "order/" + o.ID + "/finalize"

	w.Header().Set("Location", baseURL+"order/"+o.ID)
	w.WriteHeader(http.StatusCreated)
	json.NewEncoder(w).Encode(o)
}

func getOrder(w http.ResponseWriter, r *http.Request) {
	ctx := r.Context()
	db := ctx.Value(dbKey{}).(Database)
	baseUrl := r.Context().Value(baseUrlKey{}).(*url.URL).String()

	acc := ctx.Value(accContextKey{}).(*Account)

	order, err := db.GetOrder(chi.URLParam(r, "orderID"))
	if err != nil {
		AcmeError{http.StatusNotFound, "notFound", "order not found"}.Write(w)
		return
	}

	if acc.ID != order.AccountID {
		AcmeError{http.StatusUnauthorized, "unauthorized", fmt.Sprintf("account '%s' does not own order '%s'", acc.ID, order.ID)}.Write(w)
		return
	}

	if err = order.UpdateStatus(ctx, db); err != nil {
		AcmeError{http.StatusInternalServerError, "serverInternal", "error updating order"}.Write(w)
		return
	}

	w.Header().Set("Location", baseUrl+"order/"+order.ID)

	j, _ := json.Marshal(order)
	fmt.Print(j)

	json.NewEncoder(w).Encode(order)
}

func finalizeOrder(w http.ResponseWriter, r *http.Request) {
	// Should also trigger order finalization in upstream ACME provider (eg. Lets' Encrypt)
	orderId := chi.URLParam(r, "orderID")
	ctx := r.Context()
	db := ctx.Value(dbKey{}).(Database)
	acc := ctx.Value(accContextKey{}).(*Account)

	payload := payloadFromContext(ctx)

	var finalReq FinalizeRequest
	if err := json.Unmarshal(payload.Value, &finalReq); err != nil {
		AcmeError{http.StatusBadRequest, "malformed", "error unmarshaling finalize request"}.Write(w)
		return
	}

	if err := finalReq.Validate(); err != nil {
		AcmeError{http.StatusBadRequest, "malformed", err.Error()}.Write(w)
		return
	}

	order, err := db.GetOrder(orderId)
	if err != nil {
		AcmeError{http.StatusNotFound, "notFound", "order not found"}.Write(w)
		return
	}

	if acc.ID != order.AccountID {
		AcmeError{http.StatusUnauthorized, "unauthorized", fmt.Sprintf("account '%s' does not own order '%s'", acc.ID, order.ID)}.Write(w)
		return
	}

	if err = order.Finalize(ctx, db, finalReq.csr); err != nil {
		AcmeError{http.StatusInternalServerError, "serverInternal", "error finalizing order"}.Write(w)
		return
	}

	w.Header().Set("Location", r.Context().Value(baseUrlKey{}).(*url.URL).String()+"order/"+order.ID)
	json.NewEncoder(w).Encode(order)
}

// Order contains order metadata for the ACME protocol order type.
type Order struct {
	ID                string       `json:"id"`
	AccountID         string       `json:"-"`
	Status            Status       `json:"status"`
	ExpiresAt         time.Time    `json:"expires"`
	Identifiers       []Identifier `json:"identifiers"`
	NotBefore         time.Time    `json:"notBefore"`
	NotAfter          time.Time    `json:"notAfter"`
	Error             *AcmeError   `json:"error,omitempty"`
	AuthorizationIDs  []string     `json:"-"`
	AuthorizationURLs []string     `json:"authorizations"`
	FinalizeURL       string       `json:"finalize"`
	CertificateID     string       `json:"-"`
	CertificateURL    string       `json:"certificate,omitempty"`
}

// getAuthorizationFingerprint returns a fingerprint from the list of authorizations. This
// fingerprint is used on the device-attest-01 flow to verify the attestation
// certificate public key with the CSR public key.
//
// There's no point on reading all the authorizations as there will be only one
// for a permanent identifier.
func (o *Order) getAuthorizationFingerprint(db Database) (string, error) {
	for _, azID := range o.AuthorizationIDs {
		az, err := db.GetAuthorization(azID)
		if err != nil {
			return "", AcmeError{http.StatusInternalServerError, "serverInternal", "error getting authorization"}
		}
		// There's no point on reading all the authorizations as there will
		// be only one for a permanent identifier.
		if az.Fingerprint != "" {
			return az.Fingerprint, nil
		}
	}
	return "", nil
}

// UpdateStatus updates the ACME Order Status if necessary.
// Changes to the order are saved using the database interface.
func (o *Order) UpdateStatus(ctx context.Context, db Database) error {
	now := time.Now()

	switch o.Status {
	case StatusInvalid:
		return nil
	case StatusValid:
		return nil
	case StatusReady:
		// Check expiry
		if now.After(o.ExpiresAt) {
			o.Status = StatusInvalid
			o.Error = &AcmeError{http.StatusGone, "urn:ietf:params:acme:error:malformed", "order has expired"}
			break
		}
		return nil
	case StatusPending:
		// Check expiry
		if now.After(o.ExpiresAt) {
			o.Status = StatusInvalid
			o.Error = &AcmeError{http.StatusGone, "urn:ietf:params:acme:error:malformed", "order has expired"}
			break
		}

		var count = map[Status]int{
			StatusValid:   0,
			StatusInvalid: 0,
			StatusPending: 0,
		}
		for _, azID := range o.AuthorizationIDs {
			az, err := db.GetAuthorization(azID)
			if err != nil {

				return AcmeError{http.StatusInternalServerError, "urn:ietf:params:acme:error:serverInternal", "error getting authorization"}
			}
			if err = az.UpdateStatus(ctx, db); err != nil {
				return AcmeError{http.StatusInternalServerError, "urn:ietf:params:acme:error:serverInternal", fmt.Sprintf("error updating authorization ID %s", azID)}
			}
			st := az.Status
			count[st]++
		}
		switch {
		case count[StatusInvalid] > 0:
			o.Status = StatusInvalid

		// No change in the order status, so just return the order as is -
		// without writing any changes.
		case count[StatusPending] > 0:
			return nil

		case count[StatusValid] == len(o.AuthorizationIDs):
			o.Status = StatusReady

		default:
			return AcmeError{http.StatusInternalServerError, "serverInternal", "unexpected authz status"}
		}
	default:
		return AcmeError{http.StatusInternalServerError, "serverInternal", fmt.Sprintf("unrecognized order status %s", o.Status)}
	}

	if err := db.UpdateOrder(o); err != nil {
		return AcmeError{http.StatusInternalServerError, "serverInternal", "error updating order"}
	}

	return nil
}

// Finalize signs a certificate if the necessary conditions for Order completion
// have been met.
func (o *Order) Finalize(ctx context.Context, db Database, csr *x509.CertificateRequest) error {
	if err := o.UpdateStatus(ctx, db); err != nil {
		return err
	}

	switch o.Status {
	case StatusInvalid:
		return AcmeError{http.StatusGone, "malformed", fmt.Sprintf("order %s has been abandoned", o.ID)}
	case StatusValid:
		return nil
	case StatusPending:
		return AcmeError{http.StatusUnauthorized, "unauthorized", fmt.Sprintf("order %s is not ready", o.ID)}
	case StatusReady:
		break
	default:
		return AcmeError{http.StatusInternalServerError, "serverInternal", fmt.Sprintf("unexpected status %s for order %s", o.Status, o.ID)}
	}

	// Get key fingerprint if any. And then compare it with the CSR fingerprint.
	fingerprint, err := o.getAuthorizationFingerprint(db)
	if err != nil {
		return err
	}
	if fingerprint != "" {
		fp, err := keyutil.Fingerprint(csr.PublicKey)
		if err != nil {
			return AcmeError{http.StatusInternalServerError, "serverInternal", "error calculating key fingerprint"}
		}
		if subtle.ConstantTimeCompare([]byte(fingerprint), []byte(fp)) == 0 {
			return AcmeError{http.StatusUnauthorized, "unauthorized", fmt.Sprintf("order %s csr does not match the attested key", o.ID)}
		}
	}

	// canonicalize the CSR to allow for comparison
	csr = canonicalize(csr)

	// Template data
	data := x509util.NewTemplateData()
	data.SetCommonName(csr.Subject.CommonName)

	sans, err := o.sans(csr)
	if err != nil {
		return err
	}
	data.SetSubjectAlternativeNames(sans...)

	// Request the certificate

	cert := &Certificate{
		AccountID: o.AccountID,
		OrderID:   o.ID,
	}
	if err := db.CreateCert(cert); err != nil {
		return AcmeError{http.StatusInternalServerError, "serverInternal", fmt.Sprintf("error saving certificate for order %s", o.ID)}
	}

	o.CertificateID = cert.ID
	o.Status = StatusValid

	if err = db.UpdateOrder(o); err != nil {
		return AcmeError{http.StatusInternalServerError, "serverInternal", fmt.Sprintf("error updating order %s", o.ID)}
	}

	return nil
}

func (o *Order) sans(csr *x509.CertificateRequest) ([]x509util.SubjectAlternativeName, error) {
	var sans []x509util.SubjectAlternativeName

	// order the DNS names and IP addresses, so that they can be compared against the canonicalized CSR
	orderNames := make([]string, numberOfIdentifierType(DNS, o.Identifiers))
	indexDNS := 0
	for _, n := range o.Identifiers {
		switch n.Type {
		case DNS:
			orderNames[indexDNS] = n.Value
			indexDNS++
		default:
			return sans, AcmeError{http.StatusInternalServerError, "serverInternal", fmt.Sprintf("unsupported identifier type in order: %s", n.Type)}
		}
	}
	orderNames = uniqueSortedLowerNames(orderNames)

	totalNumberOfSANs := len(csr.DNSNames)
	sans = make([]x509util.SubjectAlternativeName, totalNumberOfSANs)
	index := 0

	// Validate identifier names against CSR alternative names.
	//
	// Note that with certificate templates we are not going to check for the
	// absence of other SANs as they will only be set if the template allows
	// them.
	if len(csr.DNSNames) != len(orderNames) {
		return sans, AcmeError{http.StatusBadRequest, "badCSR", fmt.Sprintf("CSR names do not match identifiers exactly: CSR names = %v, Order names = %v", csr.DNSNames, orderNames)}
	}

	for i := range csr.DNSNames {
		if csr.DNSNames[i] != orderNames[i] {
			return sans, AcmeError{http.StatusBadRequest, "badCSR", fmt.Sprintf("CSR names do not match identifiers exactly: CSR names = %v, Order names = %v", csr.DNSNames, orderNames)}
		}
		sans[index] = x509util.SubjectAlternativeName{
			Type:  x509util.DNSType,
			Value: csr.DNSNames[i],
		}
		index++
	}

	return sans, nil
}

// numberOfIdentifierType returns the number of Identifiers that
// are of type typ.
func numberOfIdentifierType(typ IdentifierType, ids []Identifier) int {
	c := 0
	for _, id := range ids {
		if id.Type == typ {
			c++
		}
	}
	return c
}

// canonicalize canonicalizes a CSR so that it can be compared against an Order
// NOTE: this effectively changes the order of SANs in the CSR, which may be OK,
// but may not be expected. It also adds a Subject Common Name to either the IP
// addresses or DNS names slice, depending on whether it can be parsed as an IP
// or not. This might result in an additional SAN in the final certificate.
func canonicalize(csr *x509.CertificateRequest) (canonicalized *x509.CertificateRequest) {
	// for clarity only; we're operating on the same object by pointer
	canonicalized = csr

	// RFC8555: The CSR MUST indicate the exact same set of requested
	// identifiers as the initial newOrder request. Identifiers of type "dns"
	// MUST appear either in the commonName portion of the requested subject
	// name or in an extensionRequest attribute [RFC2985] requesting a
	// subjectAltName extension, or both. Subject Common Names that can be
	// parsed as an IP are included as an IP address for the equality check.
	// If these were excluded, a certificate could contain an IP as the
	// common name without having been challenged.
	if csr.Subject.CommonName != "" {
		canonicalized.DNSNames = append(canonicalized.DNSNames, csr.Subject.CommonName)
	}

	canonicalized.DNSNames = uniqueSortedLowerNames(canonicalized.DNSNames)

	return canonicalized
}

// uniqueSortedLowerNames returns the set of all unique names in the input after all
// of them are lowercased. The returned names will be in their lowercased form
// and sorted alphabetically.
func uniqueSortedLowerNames(names []string) (unique []string) {
	nameMap := make(map[string]int, len(names))
	for _, name := range names {
		nameMap[strings.ToLower(name)] = 1
	}
	unique = make([]string, 0, len(nameMap))
	for name := range nameMap {
		if name != "" {
			unique = append(unique, name)
		}
	}
	sort.Strings(unique)
	return
}
