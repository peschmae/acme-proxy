package acme

import (
	"context"
	"crypto/rsa"
	"errors"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"path"
	"strings"

	"github.com/peschmae/acmepipe/pkg/database"
	"go.step.sm/crypto/jose"
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

func addDirLink(next nextHTTP) nextHTTP {
	return func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Link", r.Context().Value(baseUrlKey{}).(*url.URL).String()+"directory;rel=index")
		next(w, r)
	}
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

// verifyContentType is a middleware that verifies that content type is
// application/jose+json.
func verifyContentType(next nextHTTP) nextHTTP {
	return func(w http.ResponseWriter, r *http.Request) {

		u := &url.URL{
			Path: prefix + "cert/",
		}

		var expected []string
		if strings.Contains(r.URL.String(), u.EscapedPath()) {
			// GET /certificate requests allow a greater range of content types.
			expected = []string{"application/jose+json", "application/pkix-cert", "application/pkcs7-mime"}
		} else {
			// By default every request should have content-type applictaion/jose+json.
			expected = []string{"application/jose+json"}
		}

		ct := r.Header.Get("Content-Type")
		for _, e := range expected {
			if ct == e {
				next(w, r)
				return
			}
		}

		AcmeError{http.StatusBadRequest, "malformed", fmt.Sprintf("expected content-type to be in %s, but got %s", expected, ct)}.Write(w)

	}
}

// parseJWS is a middleware that parses a request body into a JSONWebSignature struct.
func parseJWS(next nextHTTP) nextHTTP {
	return func(w http.ResponseWriter, r *http.Request) {
		body, err := io.ReadAll(r.Body)
		if err != nil {

			AcmeError{http.StatusInternalServerError, "serverInternal", "failed to read request body"}.Write(w)
			return
		}
		jws, err := jose.ParseJWS(string(body))
		if err != nil {
			AcmeError{http.StatusBadRequest, "malformed", "failed to parse JWS from request body"}.Write(w)
			return
		}
		ctx := context.WithValue(r.Context(), jwsContextKey{}, jws)
		next(w, r.WithContext(ctx))
	}
}

// validateJWS checks the request body for to verify that it meets ACME
// requirements for a JWS.
//
// The JWS MUST NOT have multiple signatures
// The JWS Unencoded Payload Option [RFC7797] MUST NOT be used
// The JWS Unprotected Header [RFC7515] MUST NOT be used
// The JWS Payload MUST NOT be detached
// The JWS Protected Header MUST include the following fields:
//   - “alg” (Algorithm).
//     This field MUST NOT contain “none” or a Message Authentication Code
//     (MAC) algorithm (e.g. one in which the algorithm registry description
//     mentions MAC/HMAC).
//   - “nonce” (defined in Section 6.5)
//   - “url” (defined in Section 6.4)
//   - Either “jwk” (JSON Web Key) or “kid” (Key ID) as specified below<Paste>
func validateJWS(next nextHTTP) nextHTTP {
	return func(w http.ResponseWriter, r *http.Request) {
		ctx := r.Context()
		//db := ctx.Value(dbKey{}).(database.Acme)

		jws := ctx.Value(jwsContextKey{}).(*jose.JSONWebSignature)
		if jws == nil {
			// should already have happened in parseJWS
			AcmeError{http.StatusBadRequest, "malformed", "request body does not contain a JWS"}.Write(w)
			return
		}
		if len(jws.Signatures) == 0 {
			AcmeError{http.StatusBadRequest, "malformed", "request body does not contain a signature"}.Write(w)
			return
		}
		if len(jws.Signatures) > 1 {
			AcmeError{http.StatusBadRequest, "malformed", "request body contains more than one signature"}.Write(w)
			return
		}

		sig := jws.Signatures[0]
		uh := sig.Unprotected
		if uh.KeyID != "" ||
			uh.JSONWebKey != nil ||
			uh.Algorithm != "" ||
			uh.Nonce != "" ||
			len(uh.ExtraHeaders) > 0 {
			AcmeError{http.StatusBadRequest, "malformed", "unprotected header must be empty"}.Write(w)
			return
		}
		hdr := sig.Protected
		switch hdr.Algorithm {
		case jose.RS256, jose.RS384, jose.RS512, jose.PS256, jose.PS384, jose.PS512:
			if hdr.JSONWebKey != nil {
				switch k := hdr.JSONWebKey.Key.(type) {
				case *rsa.PublicKey:
					if k.Size() < MinRSAKeyBytes {
						AcmeError{http.StatusBadRequest, "malformed", fmt.Sprintf("rsa keys must be at least %d bits (%d bytes) in size",
							8*MinRSAKeyBytes, MinRSAKeyBytes)}.Write(w)
						return
					}
				default:
					AcmeError{http.StatusBadRequest, "malformed", "jws key type and algorithm do not match"}.Write(w)
					return
				}
			}
		case jose.ES256, jose.ES384, jose.ES512, jose.EdDSA:
			// we good
		default:
			AcmeError{http.StatusBadRequest, "badSignatureAlgorithm", fmt.Sprintf("unsuitable algorithm: %s", hdr.Algorithm)}.Write(w)
			return
		}

		// Check the validity/freshness of the Nonce => Isn't this already done in verifyNonce and always fails here...?
		// if err := db.DeleteNonce(ctx, acme.Nonce(hdr.Nonce)); err != nil {
		// 	render.Error(w, r, err)
		// 	return
		// }

		// Check that the JWS url matches the requested url.
		jwsURL, ok := hdr.ExtraHeaders["url"].(string)
		if !ok {
			AcmeError{http.StatusBadRequest, "malformed", "jws missing url protected header"}.Write(w)
			return
		}
		reqURL := &url.URL{Scheme: "https", Host: r.Host, Path: r.URL.Path}
		if jwsURL != reqURL.String() {
			AcmeError{http.StatusBadRequest, "malformed", fmt.Sprintf("url header in JWS (%s) does not match request url (%s)", jwsURL, reqURL)}.Write(w)
			return
		}

		if hdr.JSONWebKey != nil && hdr.KeyID != "" {
			AcmeError{http.StatusBadRequest, "malformed", "jwk and kid are mutually exclusive"}.Write(w)
			return
		}
		if hdr.JSONWebKey == nil && hdr.KeyID == "" {
			AcmeError{http.StatusBadRequest, "malformed", "either jwk or kid must be defined in jws protected header"}.Write(w)
			return
		}
		next(w, r)
	}
}

// extractJWK is a middleware that extracts the JWK from the JWS and saves it
// in the context. Make sure to parse and validate the JWS before running this
// middleware.
func extractJWK(next nextHTTP) nextHTTP {
	return func(w http.ResponseWriter, r *http.Request) {
		ctx := r.Context()
		db := ctx.Value(dbKey{}).(database.Acme)

		jws := ctx.Value(jwsContextKey{}).(*jose.JSONWebSignature)
		if jws == nil {
			// should already have happened in parseJWS
			AcmeError{http.StatusBadRequest, "malformed", "request body does not contain a JWS"}.Write(w)
			return
		}
		jwk := jws.Signatures[0].Protected.JSONWebKey
		if jwk == nil {
			AcmeError{http.StatusBadRequest, "malformed", "jwk expected in protected header"}.Write(w)
			return
		}
		if !jwk.Valid() {
			AcmeError{http.StatusBadRequest, "malformed", "invalid jwk in protected header"}.Write(w)
			return
		}

		// Overwrite KeyID with the JWK thumbprint.
		var err error
		jwk.KeyID, err = KeyToID(jwk)
		if err != nil {
			AcmeError{http.StatusInternalServerError, "serverInternal", "error getting KeyID from JWK"}.Write(w)
			return
		}

		// Store the JWK in the context.
		ctx = context.WithValue(ctx, jwkContextKey{}, jwk)

		// Get Account OR continue to generate a new one OR continue Revoke with certificate private key
		var acc *Account
		{

			tmp, err := db.GetAccountByKeyID(jwk.KeyID)
			if err != nil {
				AcmeError{http.StatusInternalServerError, "serverInternal", "error getting account by keyID"}.Write(w)
				return
			}
			if tmp != nil {
				acc = tmp.(*Account)
			} else {
				// make it excpicit
				acc = nil
			}

		}
		switch {
		case acc == nil && err == nil:
			// For NewAccount and Revoke requests ...
			break
		default:
			if !acc.IsValid() {
				AcmeError{http.StatusUnauthorized, "unauthorized", "account is not active"}.Write(w)
				return
			}
			ctx = context.WithValue(ctx, accContextKey{}, acc)
		}
		next(w, r.WithContext(ctx))
	}
}

// lookupJWK loads the JWK associated with the acme account referenced by the
// kid parameter of the signed payload.
// Make sure to parse and validate the JWS before running this middleware.
func lookupJWK(next nextHTTP) nextHTTP {
	return func(w http.ResponseWriter, r *http.Request) {
		ctx := r.Context()
		db := ctx.Value(dbKey{}).(database.Acme)

		jws := ctx.Value(jwsContextKey{}).(*jose.JSONWebSignature)
		if jws == nil {
			// should already have happened in parseJWS
			AcmeError{http.StatusBadRequest, "malformed", "request body does not contain a JWS"}.Write(w)
			return
		}

		kid := jws.Signatures[0].Protected.KeyID
		if kid == "" {
			AcmeError{http.StatusBadRequest, "malformed", "signature missing 'kid' header"}.Write(w)
			return
		}

		accID := path.Base(kid)
		// Get Account OR continue to generate a new one OR continue Revoke with certificate private key
		var acc *Account
		{

			tmp, err := db.GetAccount(accID)
			if err != nil {
				AcmeError{http.StatusInternalServerError, "serverInternal", "error getting account by keyID"}.Write(w)
				return
			}
			if tmp != nil {
				acc = tmp.(*Account)
			} else {
				// make it excpicit
				acc = nil
			}

		}

		switch {
		case acc == nil:
			AcmeError{http.StatusNotFound, "accountDoesNotExist", fmt.Sprintf("account with ID '%s' not found", accID)}.Write(w)
			return
		default:
			if !acc.IsValid() {
				AcmeError{http.StatusUnauthorized, "unauthorized", "account is not active"}.Write(w)
				return
			}

			if storedLocation := acc.GetLocation(); storedLocation != "" {
				if kid != storedLocation {
					// ACME accounts should have a stored location equivalent to the
					// kid in the ACME request.
					AcmeError{http.StatusUnauthorized, "unauthorized", fmt.Sprintf("kid does not match stored account location; expected %s, but got %s", storedLocation, kid)}.Write(w)
					return
				}

			}
			ctx = context.WithValue(ctx, accContextKey{}, acc)
			ctx = context.WithValue(ctx, jwkContextKey{}, acc.Key)
			next(w, r.WithContext(ctx))
			return
		}
	}
}

// verifyAndExtractJWSPayload extracts the JWK from the JWS and saves it in the context.
// Make sure to parse and validate the JWS before running this middleware.
func verifyAndExtractJWSPayload(next nextHTTP) nextHTTP {
	return func(w http.ResponseWriter, r *http.Request) {
		ctx := r.Context()
		jws := ctx.Value(jwsContextKey{}).(*jose.JSONWebSignature)
		if jws == nil {
			// should already have happened in parseJWS
			AcmeError{http.StatusBadRequest, "malformed", "request body does not contain a JWS"}.Write(w)
			return
		}

		jwk := ctx.Value(jwkContextKey{}).(*jose.JSONWebKey)
		if jwk == nil {
			// should already have happened in parseJWS
			AcmeError{http.StatusBadRequest, "malformed", "request body does not contain a JWK"}.Write(w)
			return
		}

		if jwk.Algorithm != "" && jwk.Algorithm != jws.Signatures[0].Protected.Algorithm {
			AcmeError{http.StatusBadRequest, "malformed", "verifier and signature algorithm do not match"}.Write(w)

			return
		}

		payload, err := jws.Verify(jwk)
		switch {
		case errors.Is(err, jose.ErrCryptoFailure):
			payload, err = retryVerificationWithPatchedSignatures(jws, jwk)
			if err != nil {
				AcmeError{http.StatusBadRequest, "malformed", "error verifying jws with patched signature(s)"}.Write(w)
				return
			}
		case err != nil:
			AcmeError{http.StatusBadRequest, "malformed", "error verifying jws"}.Write(w)
			return
		}

		ctx = context.WithValue(ctx, payloadContextKey{}, &Payload{
			Value:       payload,
			IsPostAsGet: len(payload) == 0,
			IsEmptyJSON: string(payload) == "{}",
		})
		next(w, r.WithContext(ctx))
	}
}

// retryVerificationWithPatchedSignatures retries verification of the JWS using
// the JWK by patching the JWS signatures if they're determined to be too short.
//
// Generally this shouldn't happen, but we've observed this to be the case with
// the macOS ACME client, which seems to omit (at least one) leading null
// byte(s). The error returned is `go-jose/go-jose: error in cryptographic
// primitive`, which is a sentinel error that hides the details of the actual
// underlying error, which is as follows: `go-jose/go-jose: invalid signature
// size, have 63 bytes, wanted 64`, for ES256.
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
		alg := strings.ToUpper(sig.Header.Algorithm)
		switch alg {
		case jose.ES256:
			expectedSize = 64
		case jose.ES384:
			expectedSize = 96
		case jose.ES512:
			expectedSize = 132
		default:
			// other cases are (currently) ignored
			continue
		}

		switch diff := expectedSize - len(sig.Signature); diff {
		case 0:
			// expected length; nothing to do; will result in just doing the
			// same verification (as done before calling this function) again,
			// and thus an error will be returned.
			continue
		case 1:
			patched = true
			original := make([]byte, expectedSize-diff)
			copy(original, sig.Signature)
			originalSignatureValues[i] = original

			patchedR := make([]byte, expectedSize)
			copy(patchedR[1:], original) // [0x00, R.0:31, S.0:32], for expectedSize 64
			sig.Signature = patchedR
			jws.Signatures[i] = sig

			// verify it with a patched R; return early if successful; continue
			// with patching S if not.
			data, err = jws.Verify(jwk)
			if err == nil {
				return
			}

			patchedS := make([]byte, expectedSize)
			halfSize := expectedSize / 2
			copy(patchedS, original[:halfSize])              // [R.0:32], for expectedSize 64
			copy(patchedS[halfSize+1:], original[halfSize:]) // [R.0:32, 0x00, S.0:31]
			sig.Signature = patchedS
			jws.Signatures[i] = sig
		case 2:
			// assumption is currently the Apple case, in which only the
			// first null byte of R and/or S are removed, and thus not a case in
			// which two first bytes of either R or S are removed.
			patched = true
			original := make([]byte, expectedSize-diff)
			copy(original, sig.Signature)
			originalSignatureValues[i] = original

			patchedRS := make([]byte, expectedSize)
			halfSize := expectedSize / 2
			copy(patchedRS[1:], original[:halfSize-1])          // [0x00, R.0:31], for expectedSize 64
			copy(patchedRS[halfSize+1:], original[halfSize-1:]) // [0x00, R.0:31, 0x00, S.0:31]
			sig.Signature = patchedRS
			jws.Signatures[i] = sig
		default:
			// Technically, there can be multiple null bytes in either R or S,
			// so when the difference is larger than 2, there is more than one
			// option to pick. Apple's ACME client seems to only cut off the
			// first null byte of either R or S, so we don't do anything in this
			// case. Will result in just doing the same verification (as done
			// before calling this function) again, and thus an error will be
			// returned.
			// TODO(hs): log this specific case? It might mean some other ACME
			// client is doing weird things.
			continue
		}
	}

	data, err = jws.Verify(jwk)

	return
}

// isPostAsGet asserts that the request is a PostAsGet (empty JWS payload).
func isPostAsGet(next nextHTTP) nextHTTP {
	return func(w http.ResponseWriter, r *http.Request) {
		payload := r.Context().Value(payloadContextKey{}).(*Payload)
		if payload != nil {
			AcmeError{http.StatusBadRequest, "malformed", "expected POST-as-GET"}.Write(w)
			return
		}
		if !payload.IsPostAsGet {
			AcmeError{http.StatusBadRequest, "malformed", "expected POST-as-GET"}.Write(w)
			return
		}
		next(w, r)
	}
}
