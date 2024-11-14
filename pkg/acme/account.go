package acme

import (
	"net/http"

	"github.com/go-chi/chi/v5"
)

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
