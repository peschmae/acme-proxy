package acme

import (
	"net/http"

	"github.com/go-chi/chi/v5"
)

var MinRSAKeyBytes = 256

func newOrder(w http.ResponseWriter, _ *http.Request) {
	// Should also trigger order creation in upstream ACME provider (eg. Lets' Encrypt)
	w.Write([]byte("newOrder"))
}

func getOrder(w http.ResponseWriter, r *http.Request) {
	// Only display order information, in local database, don't quyery upstream ACME provider
	orderId := chi.URLParam(r, "orderID")
	w.Write([]byte("getOrder: " + orderId))
}

func finalizeOrder(w http.ResponseWriter, r *http.Request) {
	// Should also trigger order finalization in upstream ACME provider (eg. Lets' Encrypt)
	orderId := chi.URLParam(r, "orderID")
	w.Write([]byte("finalizeOrder: " + orderId))
}
