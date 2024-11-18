package acme

import (
	"context"
	"fmt"
	"net/http"

	"go.step.sm/crypto/jose"
)

type ChallengeType string

const (
	// HTTP01 is the http-01 ACME challenge type
	HTTP01 ChallengeType = "http-01"
	// DNS01 is the dns-01 ACME challenge type
	DNS01 ChallengeType = "dns-01"
)

var (
	// InsecurePortHTTP01 is the port used to verify http-01 challenges. If not set it
	// defaults to 80.
	InsecurePortHTTP01 int

	// InsecurePortTLSALPN01 is the port used to verify tls-alpn-01 challenges. If not
	// set it defaults to 443.
	//
	// This variable can be used for testing purposes.
	InsecurePortTLSALPN01 int

	// StrictFQDN allows to enforce a fully qualified domain name in the DNS
	// resolution. By default it allows domain resolution using a search list
	// defined in the resolv.conf or similar configuration.
	StrictFQDN bool
)

// Challenge represents an ACME response Challenge type.
type Challenge struct {
	ID              string        `json:"-"`
	AccountID       string        `json:"-"`
	AuthorizationID string        `json:"-"`
	Value           string        `json:"-"`
	Type            ChallengeType `json:"type"`
	Status          Status        `json:"status"`
	Token           string        `json:"token"`
	ValidatedAt     string        `json:"validated,omitempty"`
	URL             string        `json:"url"`
	Target          string        `json:"target,omitempty"`
	Error           *AcmeError    `json:"error,omitempty"`
}

// Validate attempts to validate the Challenge. Stores changes to the Challenge
// type using the DB interface. If the Challenge is validated, the 'status' and
// 'validated' attributes are updated.
func (ch *Challenge) Validate(ctx context.Context, db DB, jwk *jose.JSONWebKey, payload []byte) error {
	// If already valid or invalid then return without performing validation.
	if ch.Status != StatusPending {
		return nil
	}
	switch ch.Type {
	case HTTP01:
		return http01Validate(ctx, ch, db, jwk)
	case DNS01:
		return dns01Validate(ctx, ch, db, jwk)
	default:
		return AcmeError{http.StatusBadRequest, "malformed", fmt.Sprintf("unexpected challenge type %q", ch.Type)}
	}
}

func http01Validate(_ context.Context, _ *Challenge, _ DB, _ *jose.JSONWebKey) error {
	return nil
}

func dns01Validate(_ context.Context, _ *Challenge, _ DB, _ *jose.JSONWebKey) error {
	return nil
}
