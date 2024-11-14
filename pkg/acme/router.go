package acme

import (
	"encoding/json"
	"net/http"
	"net/url"
	"strings"

	"github.com/go-chi/chi"
)

// Returns a dedicated Chi router, handling all ACME server endpoints
func Router() chi.Router {
	r := chi.NewRouter()

	r.Get("/", index)
	r.Get("/directory", directory)
	r.Get("/new-nonce", newNonce)
	r.Get("/new-account", newAccount)
	r.Get("/new-order", newOrder)
	r.Get("/revoke-cert", revokeCert)
	r.Get("/key-change", keyChange)

	return r

}

func index(w http.ResponseWriter, r *http.Request) {
	w.Write([]byte("ACME server running"))
}

func directory(w http.ResponseWriter, r *http.Request) {
	w.Header().Set("Content-Type", "application/json")

	u := url.URL{
		Host: r.Host,
		Path: strings.ReplaceAll(r.URL.Path, "directory", ""),
	}

	if r.TLS != nil {
		u.Scheme = "https"
	} else {
		u.Scheme = "http"
	}

	json.NewEncoder(w).Encode(map[string]string{
		"newNonce":   u.String() + "new-nonce",
		"newAccount": u.String() + "new-account",
		"newOrder":   u.String() + "new-order",
		"revokeCert": u.String() + "revoke-cert",
		"keyChange":  u.String() + "key-change",
	})

}

func newNonce(w http.ResponseWriter, _ *http.Request) {
	w.Write([]byte("newNonce"))
}

func newAccount(w http.ResponseWriter, _ *http.Request) {
	w.Write([]byte("newAccount"))
}

func newOrder(w http.ResponseWriter, _ *http.Request) {
	w.Write([]byte("newOrder"))
}

func revokeCert(w http.ResponseWriter, _ *http.Request) {
	w.Write([]byte("revokeCert"))
}

func keyChange(w http.ResponseWriter, _ *http.Request) {
	w.Write([]byte("keyChange"))
}
