package acme

import (
	"encoding/json"
	"net/http"
	"net/url"
	"strings"

	"github.com/go-chi/chi/v5"
	"github.com/peschmae/acmepipe/internal/database/sqlite"
	"github.com/peschmae/acmepipe/pkg/database"
)

var db database.Acme

// Returns a dedicated Chi router, handling all ACME server endpoints
func Router() chi.Router {
	r := chi.NewRouter()

	r.Get("/", index)
	r.Get("/directory", directory)

	r.MethodFunc("GET", "/new-nonce", addNonce(newNonce))
	r.MethodFunc("HEAD", "/new-nonce", addNonce(newNonce))

	r.MethodFunc("POST", "/new-account", addNonce(verifyNonce(newAccount)))
	r.MethodFunc("POST", "/account/{accID}", addNonce(verifyNonce(getOrUpdateAccount)))
	r.MethodFunc("POST", "/account/{accID}/orders", addNonce(verifyNonce(getAccountOrders)))

	r.MethodFunc("POST", "/new-order", addNonce(verifyNonce(newOrder)))
	r.MethodFunc("POST", "/order/{orderID}", addNonce(verifyNonce(getOrder)))
	r.MethodFunc("POST", "/order/{orderID}/finalize", addNonce(verifyNonce(finalizeOrder)))

	r.MethodFunc("POST", "/authorization/{authID}", addNonce(verifyNonce(getAuthorization)))

	r.MethodFunc("POST", "/challenger/{challengeId}", addNonce(verifyNonce(getChallenge)))

	r.MethodFunc("POST", "/cert/{certID}", addNonce(verifyNonce(getCert)))

	// currently not implemented, so we keep it simple
	r.Post("/revoke-cert", revokeCert)
	r.Post("/key-change", keyChange)

	var err error
	db, err = sqlite.NewSqliteDB()
	if err != nil {
		panic(err)
	}
	db.CreateTables()

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

func revokeCert(w http.ResponseWriter, _ *http.Request) {
	// Should also trigger certificate revocation in upstream ACME provider
	w.WriteHeader(http.StatusNotImplemented)
}

func keyChange(w http.ResponseWriter, _ *http.Request) {
	w.WriteHeader(http.StatusNotImplemented)
}

func getAuthorization(w http.ResponseWriter, r *http.Request) {
	authID := chi.URLParam(r, "authID")
	w.Write([]byte("getAuthorization: " + authID))
}

func getChallenge(w http.ResponseWriter, r *http.Request) {
	challengeId := chi.URLParam(r, "challengeId")
	w.Write([]byte("getChallenge: " + challengeId))
}

func getCert(w http.ResponseWriter, r *http.Request) {
	certID := chi.URLParam(r, "certID")
	w.Write([]byte("getCert: " + certID))
}
