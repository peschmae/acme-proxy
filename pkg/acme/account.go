package acme

import (
	"crypto"
	"encoding/base64"
	"encoding/json"
	"net/http"
	"net/url"

	"github.com/go-chi/chi/v5"
	"go.step.sm/crypto/jose"
)

// Account is a subset of the internal account type containing only those
// attributes required for responses in the ACME protocol.
type Account struct {
	ID                     string           `json:"-"`
	Key                    *jose.JSONWebKey `json:"-"`
	Contact                []string         `json:"contact,omitempty"`
	Status                 Status           `json:"status"`
	OrdersURL              string           `json:"orders"`
	ExternalAccountBinding interface{}      `json:"externalAccountBinding,omitempty"`
	LocationPrefix         string           `json:"-"`
}

// IsValid returns true if the Account is valid.
func (a *Account) IsValid() bool {
	return a.Status == StatusValid
}

// GetLocation returns the URL location of the given account.
func (a *Account) GetLocation() string {
	if a.LocationPrefix == "" {
		return ""
	}
	return a.LocationPrefix + a.ID
}

// NewAccountRequest represents the payload for a new account request.
type NewAccountRequest struct {
	Contact              []string `json:"contact"`
	OnlyReturnExisting   bool     `json:"onlyReturnExisting"`
	TermsOfServiceAgreed bool     `json:"termsOfServiceAgreed"`
}

func validateContacts(cs []string) error {
	for _, c := range cs {
		if c == "" {
			return AcmeError{http.StatusBadRequest, "malformed", "contact cannot be empty"}
		}
		// only mailto: contacts are supported
		if c[:7] != "mailto:" {
			return AcmeError{http.StatusBadRequest, "unsupportedContact", "only mailto: contacts are supported"}
		}
	}

	return nil
}

// Validate validates a new-account request body.
func (n *NewAccountRequest) Validate() error {
	if n.OnlyReturnExisting && len(n.Contact) > 0 {
		return AcmeError{http.StatusBadRequest, "malformed", "onlyReturnExisting and contact cannot be used together"}
	}
	return validateContacts(n.Contact)
}

func newAccount(w http.ResponseWriter, r *http.Request) {
	baseUrl := r.Context().Value(baseUrlKey{}).(*url.URL).String()

	payload := payloadFromContext(r.Context())
	var newAccountReq NewAccountRequest
	if err := json.Unmarshal(payload.Value, &newAccountReq); err != nil {
		AcmeError{http.StatusBadRequest, "malformed", "malformed JSON in request body"}.Write(w)

		return
	}

	if err := newAccountReq.Validate(); err != nil {
		if acmeErr, ok := err.(AcmeError); ok {
			acmeErr.Write(w)
		}
		return
	}

	// Create a new account
	acc := &Account{
		Key:     r.Context().Value(jwkContextKey{}).(*jose.JSONWebKey),
		Status:  StatusValid,
		Contact: newAccountReq.Contact,
	}
	db := r.Context().Value(dbKey{}).(Database)
	if err := db.CreateAccount(acc); err != nil {
		AcmeError{http.StatusInternalServerError, "serverInternal", "error creating account"}.Write(w)
		return
	}

	// Return the account
	w.Header().Set("Location", baseUrl+"/acme/account/"+acc.ID)
	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(acc)

}

func getOrUpdateAccount(w http.ResponseWriter, r *http.Request) {
	// Only display account information, in local database, don't quyery upstream ACME provider
	accId := chi.URLParam(r, "accID")

	w.Write([]byte("getOrUpdateAccount: " + accId))
}

func getAccountOrders(w http.ResponseWriter, r *http.Request) {
	// Fetch local orders
	accId := chi.URLParam(r, "accID")
	w.Write([]byte("getAccountOrders: " + accId))
}

// KeyToID converts a JWK to a thumbprint.
func KeyToID(jwk *jose.JSONWebKey) (string, error) {
	kid, err := jwk.Thumbprint(crypto.SHA256)
	if err != nil {
		return "", err
	}
	return base64.RawURLEncoding.EncodeToString(kid), nil
}
