package acme

import "context"

// PublicCA is everything on the Public side, seen from the Internal side.
// Implementations own the Public Account, the Public Order and the DNS-01
// Public Challenge through the DNS Provider.
type PublicCA interface {
	// Issue places exactly one Public Order for the CSR, which must be
	// forwarded unchanged, and returns the issued chain as PEM (leaf first).
	// A failure reported by the Public CA should be returned as (or wrap) a
	// *Problem so that it reaches the Requester unchanged.
	Issue(ctx context.Context, csrDER []byte, identifiers []Identifier) (chainPEM []byte, err error)

	// Revoke revokes a certificate previously returned by Issue.
	Revoke(ctx context.Context, certDER []byte, reason int) error
}
