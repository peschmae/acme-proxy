package acme

import (
	"net/http"

	"github.com/peschmae/acmepipe/pkg/database"
)

type nextHTTP = func(http.ResponseWriter, *http.Request)

// default middleware adding baseUrl to context
func baseUrlContext(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		ctx := newBaseURLContext(r.Context(), r)

		next.ServeHTTP(w, r.WithContext(ctx))
	})
}

func databaseContext(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		ctx := newDBContext(r.Context())

		next.ServeHTTP(w, r.WithContext(ctx))
	})
}

// addNonce creates a new Nonce and adds it to the response headers.
func addNonce(next nextHTTP) nextHTTP {
	return func(w http.ResponseWriter, r *http.Request) {
		db := r.Context().Value(dbKey{}).(database.Acme)

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

// verifyNonce checks the request headers for a valid Nonce, and deletes it from the database.
func verifyNonce(next nextHTTP) nextHTTP {
	return func(w http.ResponseWriter, r *http.Request) {
		nonce := r.Header.Get("Replay-Nonce")
		if nonce == "" {
			w.WriteHeader(http.StatusPreconditionRequired)
			return
		}

		db := r.Context().Value(dbKey{}).(database.Acme)
		err := db.DeleteNonce(nonce)
		if err != nil {
			w.WriteHeader(http.StatusPreconditionFailed)
			return
		}

		next(w, r)
	}
}
