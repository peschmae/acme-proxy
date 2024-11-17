package acme

import (
	"errors"
	"net/http"

	"github.com/go-chi/chi/v5"
)

// NewAccountRequest represents the payload for a new account request.
type NewAccountRequest struct {
	Contact              []string `json:"contact"`
	OnlyReturnExisting   bool     `json:"onlyReturnExisting"`
	TermsOfServiceAgreed bool     `json:"termsOfServiceAgreed"`
}

func validateContacts(cs []string) error {
	for _, c := range cs {
		if c == "" {
			return errors.New("contact cannot be empty")
		}
	}
	return nil
}

// Validate validates a new-account request body.
func (n *NewAccountRequest) Validate() error {
	if n.OnlyReturnExisting && len(n.Contact) > 0 {
		return errors.New("onlyReturnExisting and contact cannot be used together")
	}
	return validateContacts(n.Contact)
}

func newAccount(w http.ResponseWriter, _ *http.Request) {
	// Should also trigger account creation in upstream ACME provider (eg. Lets' Encrypt)
	w.Write([]byte("newAccount"))
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
