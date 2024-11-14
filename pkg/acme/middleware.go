package acme

import "net/http"

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
