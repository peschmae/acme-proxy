package acme

type Nonce string

// NonceStore is a simple interface to store and retrieve Nonces
type NonceStore interface {
	CreateNonce() (Nonce, error)
	DeleteNonce(nonce Nonce) error
}
