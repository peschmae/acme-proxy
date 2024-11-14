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

	r.Get("/new-order", newOrder)
	r.Get("/revoke-cert", revokeCert)
	r.Get("/key-change", keyChange)

	var err error
	db, err = sqlite.NewSqliteDB()
	if err != nil {
		panic(err)
	}

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
	w.WriteHeader(http.StatusNotImplemented)
}

func keyChange(w http.ResponseWriter, _ *http.Request) {
	w.WriteHeader(http.StatusNotImplemented)
}

type nextHTTP = func(http.ResponseWriter, *http.Request)

// addNonce is a middleware that adds a nonce to the response header.
func addNonce(next nextHTTP) nextHTTP {
	return func(w http.ResponseWriter, r *http.Request) {
		nonce, err := db.CreateNonce()
		if err != nil {
			w.Write([]byte("error creating nonce"))
			return
		}
		w.Header().Set("Replay-Nonce", string(nonce))
		w.Header().Set("Cache-Control", "no-store")

		next(w, r)
	}
}

func verifyNonce(next nextHTTP) nextHTTP {
	return func(w http.ResponseWriter, r *http.Request) {
		nonce := r.Header.Get("Replay-Nonce")
		if nonce == "" {
			w.WriteHeader(http.StatusPreconditionRequired)
			return
		}

		err := db.DeleteNonce(nonce)
		if err != nil {
			w.WriteHeader(http.StatusPreconditionFailed)
			return
		}

		next(w, r)
	}
}
