package acme

import (
	"encoding/json"
	"net/http"
	"net/url"

	"github.com/go-chi/chi/v5"
)

// ToDo: move to config or something
var prefix = "/acme/"

// Returns a dedicated Chi router, handling all ACME server endpoints
func Router() chi.Router {
	r := chi.NewRouter()

	r.Use(baseUrlContext)
	r.Use(databaseContext)

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

	return r

}

func index(w http.ResponseWriter, r *http.Request) {
	w.Write([]byte("ACME server running"))
}

func directory(w http.ResponseWriter, r *http.Request) {
	w.Header().Set("Content-Type", "application/json")

	baseUrl := r.Context().Value(baseUrlKey{}).(*url.URL).String()

	json.NewEncoder(w).Encode(map[string]string{
		"newNonce":   baseUrl + "new-nonce",
		"newAccount": baseUrl + "new-account",
		"newOrder":   baseUrl + "new-order",
		"revokeCert": baseUrl + "revoke-cert",
		"keyChange":  baseUrl + "key-change",
	})

}

// implements RFC 8555 section 7.2 "Getting a Nonce"
func newNonce(w http.ResponseWriter, r *http.Request) {

	w.Header().Set("Link", r.Context().Value(baseUrlKey{}).(*url.URL).String()+"directory;rel=index")

	w.WriteHeader(http.StatusNoContent)
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
