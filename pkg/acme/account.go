package acme

import (
	"encoding/json"
	"errors"
	"net/http"
	"strings"
	"time"

	"github.com/go-chi/chi/v5"
)

type accountResponse struct {
	Status  Status   `json:"status"`
	Contact []string `json:"contact,omitempty"`
	Orders  string   `json:"orders"`
}

func renderAccount(r *http.Request, a *Account) accountResponse {
	return accountResponse{Status: a.Status, Contact: a.Contact, Orders: linkURL(r, "account", a.ID, "orders")}
}

func validateContacts(cs []string) error {
	for _, c := range cs {
		if !strings.HasPrefix(c, "mailto:") {
			return NewProblem(http.StatusBadRequest, "unsupportedContact", "only mailto: contacts are supported, got %q", c)
		}
		if len(c) == len("mailto:") {
			return NewProblem(http.StatusBadRequest, "invalidContact", "empty mailto: contact")
		}
	}
	return nil
}

// newAccount implements RFC 8555 §7.3. Registration is open: anyone who can
// reach acme-proxy may create an Internal Account.
func (s *Server) newAccount(w http.ResponseWriter, r *http.Request) {
	var req struct {
		Contact              []string `json:"contact"`
		OnlyReturnExisting   bool     `json:"onlyReturnExisting"`
		TermsOfServiceAgreed bool     `json:"termsOfServiceAgreed"`
	}
	if err := json.Unmarshal(payloadFrom(r).value, &req); err != nil {
		writeProblem(w, malformed("malformed JSON in request body"))
		return
	}

	if acc := accountFrom(r); acc != nil {
		if acc.Status != StatusValid {
			writeProblem(w, unauthorized("account is %s", acc.Status))
			return
		}
		w.Header().Set("Location", linkURL(r, "account", acc.ID))
		writeJSON(w, http.StatusOK, renderAccount(r, acc))
		return
	}
	if req.OnlyReturnExisting {
		writeProblem(w, NewProblem(http.StatusBadRequest, "accountDoesNotExist", "no account exists for this key"))
		return
	}
	if err := validateContacts(req.Contact); err != nil {
		writeProblem(w, err)
		return
	}

	jwk := jwkFrom(r)
	tp, err := keyThumbprint(jwk)
	if err != nil {
		writeProblem(w, serverInternal("error computing JWK thumbprint"))
		return
	}
	acc := &Account{
		KeyID:     tp,
		Key:       jwk,
		Contact:   req.Contact,
		Status:    StatusValid,
		CreatedAt: time.Now(),
	}
	if err := s.store.CreateAccount(acc); err != nil {
		writeProblem(w, serverInternal("error creating account"))
		return
	}
	s.log.Info("internal account created", "account", acc.ID)
	w.Header().Set("Location", linkURL(r, "account", acc.ID))
	writeJSON(w, http.StatusCreated, renderAccount(r, acc))
}

// account fetches (POST-as-GET), updates contacts, or deactivates an account
// (RFC 8555 §7.3.2, §7.3.6).
func (s *Server) account(w http.ResponseWriter, r *http.Request) {
	acc := accountFrom(r)
	if chi.URLParam(r, "accID") != acc.ID {
		writeProblem(w, unauthorized("account URL does not match the signing account"))
		return
	}
	p := payloadFrom(r)
	if !p.isPostAsGet {
		var req struct {
			Status  Status    `json:"status"`
			Contact *[]string `json:"contact"`
		}
		if err := json.Unmarshal(p.value, &req); err != nil {
			writeProblem(w, malformed("malformed JSON in request body"))
			return
		}
		switch req.Status {
		case "":
		case StatusDeactivated:
			acc.Status = StatusDeactivated
		default:
			writeProblem(w, malformed("account status can only be changed to %q", StatusDeactivated))
			return
		}
		if req.Contact != nil {
			if err := validateContacts(*req.Contact); err != nil {
				writeProblem(w, err)
				return
			}
			acc.Contact = *req.Contact
		}
		if err := s.store.UpdateAccount(acc); err != nil {
			writeProblem(w, serverInternal("error updating account"))
			return
		}
		if acc.Status == StatusDeactivated {
			s.log.Info("internal account deactivated", "account", acc.ID)
		}
	}
	w.Header().Set("Location", linkURL(r, "account", acc.ID))
	writeJSON(w, http.StatusOK, renderAccount(r, acc))
}

// accountOrders lists the account's Internal Orders (RFC 8555 §7.1.2.1).
func (s *Server) accountOrders(w http.ResponseWriter, r *http.Request) {
	acc := accountFrom(r)
	if chi.URLParam(r, "accID") != acc.ID {
		writeProblem(w, unauthorized("account URL does not match the signing account"))
		return
	}
	orders, err := s.store.GetOrdersByAccountID(acc.ID)
	if err != nil && !errors.Is(err, ErrNotFound) {
		writeProblem(w, serverInternal("error listing orders"))
		return
	}
	urls := make([]string, 0, len(orders))
	for _, o := range orders {
		urls = append(urls, linkURL(r, "order", o.ID))
	}
	writeJSON(w, http.StatusOK, map[string][]string{"orders": urls})
}
