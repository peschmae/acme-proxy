package acme

import (
	"context"
	"encoding/json"
	"fmt"
	"net/http"
	"net/url"
	"time"

	"github.com/go-chi/chi/v5"
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
	ValidatedAt     time.Time     `json:"validated,omitempty"`
	URL             string        `json:"url"`
	Target          string        `json:"target,omitempty"`
	Error           *AcmeError    `json:"error,omitempty"`
}

// Validate attempts to validate the Challenge. Stores changes to the Challenge
// type using the DB interface. If the Challenge is validated, the 'status' and
// 'validated' attributes are updated.
func (ch *Challenge) Validate(ctx context.Context, jwk *jose.JSONWebKey, payload []byte) error {
	// If already valid or invalid then return without performing validation.
	if ch.Status != StatusPending {
		return nil
	}
	switch ch.Type {
	case HTTP01:
		return http01Validate(ctx, ch, jwk)
	case DNS01:
		return dns01Validate(ctx, ch, jwk)
	default:
		return AcmeError{http.StatusBadRequest, "malformed", fmt.Sprintf("unexpected challenge type %q", ch.Type)}
	}
}

func http01Validate(ctx context.Context, chall *Challenge, _ *jose.JSONWebKey) error {
	// If the challenge is already valid or invalid, return early.

	chall.Status = StatusValid
	chall.ValidatedAt = time.Now()
	// Update the challenge in the database
	db := ctx.Value(dbKey{}).(Database)
	if err := db.UpdateChallenge(chall); err != nil {
		return AcmeError{http.StatusInternalServerError, "serverInternal", "error updating challenge"}
	}

	return nil
}

func dns01Validate(ctx context.Context, chall *Challenge, _ *jose.JSONWebKey) error {
	// Fake validate for now
	chall.Status = StatusValid
	chall.ValidatedAt = time.Now()
	// Update the challenge in the database.
	db := ctx.Value(dbKey{}).(Database)
	if err := db.UpdateChallenge(chall); err != nil {
		return AcmeError{http.StatusInternalServerError, "serverInternal", "error updating challenge"}
	}

	return nil
}

func getChallenge(w http.ResponseWriter, r *http.Request) {
	challengeId := chi.URLParam(r, "challengeId")
	ctx := r.Context()
	db := ctx.Value(dbKey{}).(Database)
	acc := ctx.Value(accContextKey{}).(*Account)
	baseUrl := r.Context().Value(baseUrlKey{}).(*url.URL).String()
	jwk := r.Context().Value(jwkContextKey{}).(*jose.JSONWebKey)

	payload := payloadFromContext(ctx)

	chall, err := db.GetChallenge(challengeId)
	if err != nil {
		switch err.(type) {
		case *AcmeError:
			err.(AcmeError).Write(w)
			return
		default:
			if err == ErrNotFound {
				AcmeError{http.StatusNotFound, "notFound", "challenge not found"}.Write(w)
				return
			}
			AcmeError{http.StatusInternalServerError, "serverInternal", "error getting challenge"}.Write(w)
			return
		}
	}

	if chall.AccountID != acc.ID {
		AcmeError{http.StatusUnauthorized, "unauthorized", "account does not own challenge"}.Write(w)
		return
	}

	if err := chall.Validate(ctx, jwk, payload.Value); err != nil {

		switch err.(type) {
		case *AcmeError:
			err.(AcmeError).Write(w)
			return
		default:
			if err == ErrNotFound {
				AcmeError{http.StatusNotFound, "notFound", "challenge not found"}.Write(w)
				return
			}
			AcmeError{http.StatusInternalServerError, "serverInternal", "error validating challenge"}.Write(w)
			return
		}
	}

	// link all challenges to the authz
	chall.URL = baseUrl + "challenge/" + chall.ID

	w.Header().Add("Link", baseUrl+"authorization/"+chall.AuthorizationID+";rel=\"up\"")
	w.Header().Add("Location", chall.URL)

	json.NewEncoder(w).Encode(chall)
}
