package acme

import (
	"crypto/x509"
	"net/http"

	"github.com/go-chi/chi/v5"
)

// Certificate options with which to create and store a cert object.
type Certificate struct {
	ID            string
	AccountID     string
	OrderID       string
	Leaf          *x509.Certificate
	Intermediates []*x509.Certificate
}

func getCert(w http.ResponseWriter, r *http.Request) {
	certID := chi.URLParam(r, "certID")
	w.Write([]byte("getCert: " + certID))
}
