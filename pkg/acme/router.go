package acme

import (
	"encoding/json"
	"net/http"
	"net/url"
	"strings"

	"github.com/go-chi/chi/v5"
)

type AcmeError struct {
	Status int    `json:"status"`
	Type   string `json:"type"`
	Detail string `json:"detail"`
}

func (e AcmeError) Error() string {
	return e.Detail
}

func (e AcmeError) Write(w http.ResponseWriter) {
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(e.Status)

	officialACMEPrefix := "urn:ietf:params:acme:error:"
	if !strings.Contains(e.Type, officialACMEPrefix) {
		e.Type = officialACMEPrefix + e.Type
	}
	json.NewEncoder(w).Encode(e)

}

// ToDo: move to config or something
var prefix = "/acme/"

// Returns a dedicated Chi router, handling all ACME server endpoints
func Router() chi.Router {
	r := chi.NewRouter()

	r.Use(baseUrlContext)
	r.Use(databaseContext)

	r.Get("/", index)
	r.Get("/directory", directory)

	r.MethodFunc("GET", "/new-nonce", addNonce(addDirLink(newNonce)))
	r.MethodFunc("HEAD", "/new-nonce", addNonce(addDirLink(newNonce)))

	validatingMiddleware := func(next nextHTTP) nextHTTP {
		return addNonce(addDirLink(verifyContentType(parseJWS(validateJWS(next)))))
	}
	extractPayloadByJWK := func(next nextHTTP) nextHTTP {
		return validatingMiddleware(extractJWK(verifyAndExtractJWSPayload(next)))
	}
	extractPayloadByKid := func(next nextHTTP) nextHTTP {
		return validatingMiddleware(lookupJWK(verifyAndExtractJWSPayload(next)))
	}

	r.MethodFunc("POST", "/new-account", extractPayloadByJWK(newAccount))
	r.MethodFunc("POST", "/account/{accID}", extractPayloadByKid(getOrUpdateAccount))
	r.MethodFunc("POST", "/account/{accID}/orders", extractPayloadByKid(isPostAsGet(getAccountOrders)))

	r.MethodFunc("POST", "/new-order", extractPayloadByKid(newOrder))
	r.MethodFunc("POST", "/order/{orderID}", extractPayloadByKid(isPostAsGet(getOrder)))
	r.MethodFunc("POST", "/order/{orderID}/finalize", extractPayloadByKid(finalizeOrder))

	r.MethodFunc("POST", "/authorization/{authID}", extractPayloadByKid(isPostAsGet(getAuthorization)))

	r.MethodFunc("POST", "/challenger/{challengeId}", extractPayloadByKid(isPostAsGet(getChallenge)))

	r.MethodFunc("POST", "/cert/{certID}", extractPayloadByKid(isPostAsGet(getCert)))

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
