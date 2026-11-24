package acme

import (
	"context"
	"crypto"
	"crypto/rsa"
	"encoding/base64"
	"errors"
	"io"
	"net/http"
	"strings"

	"go.step.sm/crypto/jose"
)

type ctxKey int

const (
	ctxJWS ctxKey = iota
	ctxJWK
	ctxAccount
	ctxPayload
)

// minRSAKeyBytes is the minimum RSA account key size (2048 bits).
const minRSAKeyBytes = 256

// payload is the verified JWS payload of a request.
type payload struct {
	value []byte
	// isPostAsGet is true for an empty payload (RFC 8555 §6.3).
	isPostAsGet bool
}

func payloadFrom(r *http.Request) *payload {
	p, _ := r.Context().Value(ctxPayload).(*payload)
	return p
}
func accountFrom(r *http.Request) *Account {
	a, _ := r.Context().Value(ctxAccount).(*Account)
	return a
}
func jwkFrom(r *http.Request) *jose.JSONWebKey {
	k, _ := r.Context().Value(ctxJWK).(*jose.JSONWebKey)
	return k
}
func jwsFrom(r *http.Request) *jose.JSONWebSignature {
	j, _ := r.Context().Value(ctxJWS).(*jose.JSONWebSignature)
	return j
}

func withValue(r *http.Request, k ctxKey, v any) *http.Request {
	return r.WithContext(context.WithValue(r.Context(), k, v))
}

// keyThumbprint returns the base64url SHA-256 JWK thumbprint (RFC 7638).
func keyThumbprint(jwk *jose.JSONWebKey) (string, error) {
	tp, err := jwk.Thumbprint(crypto.SHA256)
	if err != nil {
		return "", err
	}
	return base64.RawURLEncoding.EncodeToString(tp), nil
}

// withNonce adds a fresh Replay-Nonce and the directory Link to every response.
func (s *Server) withNonce(next http.HandlerFunc) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		nonce, err := s.store.CreateNonce()
		if err != nil {
			writeProblem(w, serverInternal("error creating nonce"))
			return
		}
		w.Header().Set("Replay-Nonce", nonce)
		w.Header().Set("Cache-Control", "no-store")
		w.Header().Add("Link", `<`+linkURL(r, "directory")+`>;rel="index"`)
		next(w, r)
	}
}

// byJWK authenticates a request signed with an embedded "jwk" (new-account).
// The account for that key, if any, is put in the context.
func (s *Server) byJWK(next http.HandlerFunc) http.HandlerFunc {
	return s.withNonce(s.parseJWS(s.extractJWK(s.verifyPayload(next))))
}

// byKid authenticates a request signed by an existing Internal Account ("kid").
func (s *Server) byKid(next http.HandlerFunc) http.HandlerFunc {
	return s.withNonce(s.parseJWS(s.lookupKid(s.verifyPayload(next))))
}

// byKidOrJWK accepts either form (revoke-cert).
func (s *Server) byKidOrJWK(next http.HandlerFunc) http.HandlerFunc {
	kid := s.lookupKid(s.verifyPayload(next))
	jwk := s.extractJWK(s.verifyPayload(next))
	return s.withNonce(s.parseJWS(func(w http.ResponseWriter, r *http.Request) {
		if jwsFrom(r).Signatures[0].Protected.KeyID != "" {
			kid(w, r)
			return
		}
		jwk(w, r)
	}))
}

// parseJWS parses the body and enforces RFC 8555 §6.2 and §6.4/6.5.
func (s *Server) parseJWS(next http.HandlerFunc) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		if ct := r.Header.Get("Content-Type"); ct != "application/jose+json" {
			writeProblem(w, malformed("expected Content-Type application/jose+json, got %q", ct))
			return
		}
		body, err := io.ReadAll(io.LimitReader(r.Body, 1<<20))
		if err != nil {
			writeProblem(w, serverInternal("failed to read request body"))
			return
		}
		jws, err := jose.ParseJWS(string(body))
		if err != nil {
			writeProblem(w, malformed("failed to parse JWS from request body"))
			return
		}
		if len(jws.Signatures) != 1 {
			writeProblem(w, malformed("request body must contain exactly one signature"))
			return
		}
		sig := jws.Signatures[0]
		uh := sig.Unprotected
		if uh.KeyID != "" || uh.JSONWebKey != nil || uh.Algorithm != "" || uh.Nonce != "" || len(uh.ExtraHeaders) > 0 {
			writeProblem(w, malformed("unprotected header must be empty"))
			return
		}
		hdr := sig.Protected
		switch hdr.Algorithm {
		case jose.RS256, jose.RS384, jose.RS512, jose.PS256, jose.PS384, jose.PS512:
			if hdr.JSONWebKey != nil {
				k, ok := hdr.JSONWebKey.Key.(*rsa.PublicKey)
				if !ok {
					writeProblem(w, malformed("jws key type and algorithm do not match"))
					return
				}
				if k.Size() < minRSAKeyBytes {
					writeProblem(w, malformed("rsa keys must be at least %d bits", 8*minRSAKeyBytes))
					return
				}
			}
		case jose.ES256, jose.ES384, jose.ES512, jose.EdDSA:
		default:
			writeProblem(w, NewProblem(http.StatusBadRequest, "badSignatureAlgorithm", "unsuitable algorithm: %s", hdr.Algorithm))
			return
		}

		if err := s.store.ConsumeNonce(hdr.Nonce); err != nil {
			writeProblem(w, NewProblem(http.StatusBadRequest, "badNonce", "nonce is invalid or has expired"))
			return
		}

		jwsURL, _ := hdr.ExtraHeaders["url"].(string)
		if jwsURL == "" {
			writeProblem(w, malformed("jws missing url protected header"))
			return
		}
		scheme := "https"
		if r.TLS == nil {
			scheme = "http"
		}
		if reqURL := scheme + "://" + r.Host + r.URL.Path; jwsURL != reqURL {
			writeProblem(w, malformed("url header in JWS (%s) does not match request url (%s)", jwsURL, reqURL))
			return
		}

		if hdr.JSONWebKey != nil && hdr.KeyID != "" {
			writeProblem(w, malformed("jwk and kid are mutually exclusive"))
			return
		}
		if hdr.JSONWebKey == nil && hdr.KeyID == "" {
			writeProblem(w, malformed("either jwk or kid must be defined in jws protected header"))
			return
		}
		next(w, withValue(r, ctxJWS, jws))
	}
}

// extractJWK takes the key from the "jwk" header and loads its account, if any.
func (s *Server) extractJWK(next http.HandlerFunc) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		jwk := jwsFrom(r).Signatures[0].Protected.JSONWebKey
		if jwk == nil {
			writeProblem(w, malformed("jwk expected in protected header"))
			return
		}
		if !jwk.Valid() {
			writeProblem(w, malformed("invalid jwk in protected header"))
			return
		}
		r = withValue(r, ctxJWK, jwk)

		tp, err := keyThumbprint(jwk)
		if err != nil {
			writeProblem(w, serverInternal("error computing JWK thumbprint"))
			return
		}
		acc, err := s.store.GetAccountByKeyID(tp)
		switch {
		case errors.Is(err, ErrNotFound):
			// new-account for an unknown key, or revocation by certificate key.
		case err != nil:
			writeProblem(w, serverInternal("error loading account"))
			return
		default:
			r = withValue(r, ctxAccount, acc)
		}
		next(w, r)
	}
}

// lookupKid loads the account referenced by the "kid" header and uses its key.
func (s *Server) lookupKid(next http.HandlerFunc) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		kid := jwsFrom(r).Signatures[0].Protected.KeyID
		if kid == "" {
			writeProblem(w, malformed("signature missing 'kid' header"))
			return
		}
		prefix := linkURL(r, "account") + "/"
		accID := strings.TrimPrefix(kid, prefix)
		if accID == kid || accID == "" || strings.Contains(accID, "/") {
			writeProblem(w, NewProblem(http.StatusBadRequest, "accountDoesNotExist", "kid %q is not an account URL of this server", kid))
			return
		}
		acc, err := s.store.GetAccount(accID)
		if errors.Is(err, ErrNotFound) {
			writeProblem(w, NewProblem(http.StatusBadRequest, "accountDoesNotExist", "account %q does not exist", accID))
			return
		}
		if err != nil {
			writeProblem(w, serverInternal("error loading account"))
			return
		}
		if acc.Status != StatusValid {
			writeProblem(w, unauthorized("account is %s", acc.Status))
			return
		}
		r = withValue(r, ctxAccount, acc)
		r = withValue(r, ctxJWK, acc.Key)
		next(w, r)
	}
}

// verifyPayload verifies the signature with the key in context and stores the payload.
func (s *Server) verifyPayload(next http.HandlerFunc) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		jws := jwsFrom(r)
		jwk := jwkFrom(r)
		if jwk.Algorithm != "" && jwk.Algorithm != jws.Signatures[0].Protected.Algorithm {
			writeProblem(w, malformed("verifier and signature algorithm do not match"))
			return
		}
		data, err := jws.Verify(jwk)
		if errors.Is(err, jose.ErrCryptoFailure) {
			data, err = retryVerificationWithPatchedSignatures(jws, jwk)
		}
		if err != nil {
			writeProblem(w, malformed("error verifying jws"))
			return
		}
		next(w, withValue(r, ctxPayload, &payload{value: data, isPostAsGet: len(data) == 0}))
	}
}

// postAsGet rejects requests that are not POST-as-GET (RFC 8555 §6.3).
func postAsGet(next http.HandlerFunc) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		if !payloadFrom(r).isPostAsGet {
			writeProblem(w, malformed("expected POST-as-GET"))
			return
		}
		next(w, r)
	}
}

// retryVerificationWithPatchedSignatures retries verification of ECDSA
// signatures that lost leading zero bytes, as observed with the macOS ACME
// client (taken from smallstep/certificates).
func retryVerificationWithPatchedSignatures(jws *jose.JSONWebSignature, jwk *jose.JSONWebKey) (data []byte, err error) {
	originalSignatureValues := make([][]byte, len(jws.Signatures))
	patched := false
	defer func() {
		if patched && err != nil {
			for i, sig := range jws.Signatures {
				sig.Signature = originalSignatureValues[i]
				jws.Signatures[i] = sig
			}
		}
	}()
	for i, sig := range jws.Signatures {
		var expectedSize int
		switch strings.ToUpper(sig.Header.Algorithm) {
		case jose.ES256:
			expectedSize = 64
		case jose.ES384:
			expectedSize = 96
		case jose.ES512:
			expectedSize = 132
		default:
			continue
		}
		switch diff := expectedSize - len(sig.Signature); diff {
		case 1:
			patched = true
			original := make([]byte, expectedSize-diff)
			copy(original, sig.Signature)
			originalSignatureValues[i] = original

			patchedR := make([]byte, expectedSize)
			copy(patchedR[1:], original)
			sig.Signature = patchedR
			jws.Signatures[i] = sig
			if data, err = jws.Verify(jwk); err == nil {
				return
			}
			patchedS := make([]byte, expectedSize)
			half := expectedSize / 2
			copy(patchedS, original[:half])
			copy(patchedS[half+1:], original[half:])
			sig.Signature = patchedS
			jws.Signatures[i] = sig
		case 2:
			patched = true
			original := make([]byte, expectedSize-diff)
			copy(original, sig.Signature)
			originalSignatureValues[i] = original

			patchedRS := make([]byte, expectedSize)
			half := expectedSize / 2
			copy(patchedRS[1:], original[:half-1])
			copy(patchedRS[half+1:], original[half-1:])
			sig.Signature = patchedRS
			jws.Signatures[i] = sig
		}
	}
	return jws.Verify(jwk)
}
