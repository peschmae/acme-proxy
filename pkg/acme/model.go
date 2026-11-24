package acme

import (
	"time"

	"go.step.sm/crypto/jose"
)

// Status is an ACME resource status (RFC 8555 §7.1.6).
type Status string

const (
	StatusPending     Status = "pending"
	StatusReady       Status = "ready"
	StatusProcessing  Status = "processing"
	StatusValid       Status = "valid"
	StatusInvalid     Status = "invalid"
	StatusDeactivated Status = "deactivated"
)

// IdentifierType is an ACME identifier type. acme-proxy only supports DNS.
type IdentifierType string

const IdentifierDNS IdentifierType = "dns"

// Identifier is a DNS name within the Internal Domain that a certificate is
// requested for.
type Identifier struct {
	Type  IdentifierType `json:"type"`
	Value string         `json:"value"`
}

// ChallengeType is an ACME challenge type. acme-proxy only offers http-01 as
// Internal Challenge.
type ChallengeType string

const ChallengeHTTP01 ChallengeType = "http-01"

// Account is an Internal Account: a Requester's ACME account with acme-proxy.
type Account struct {
	ID        string           `json:"id"`
	KeyID     string           `json:"keyID"` // base64url SHA-256 JWK thumbprint
	Key       *jose.JSONWebKey `json:"key"`
	Contact   []string         `json:"contact,omitempty"`
	Status    Status           `json:"status"`
	CreatedAt time.Time        `json:"createdAt"`
}

// Order is an Internal Order.
type Order struct {
	ID               string       `json:"id"`
	AccountID        string       `json:"accountID"`
	Status           Status       `json:"status"`
	Identifiers      []Identifier `json:"identifiers"`
	AuthorizationIDs []string     `json:"authorizationIDs"`
	NotBefore        time.Time    `json:"notBefore"`
	NotAfter         time.Time    `json:"notAfter"`
	ExpiresAt        time.Time    `json:"expiresAt"`
	CreatedAt        time.Time    `json:"createdAt"`
	CSR              []byte       `json:"csr,omitempty"`
	CertificateID    string       `json:"certificateID,omitempty"`
	Error            *Problem     `json:"error,omitempty"`
}

// Authorization is an Internal Authorization for one Identifier of one
// Internal Order. For a wildcard Identifier the stored Identifier is the
// Wildcard Base and Wildcard is true.
type Authorization struct {
	ID           string     `json:"id"`
	AccountID    string     `json:"accountID"`
	OrderID      string     `json:"orderID"`
	Identifier   Identifier `json:"identifier"`
	Wildcard     bool       `json:"wildcard"`
	Status       Status     `json:"status"`
	ChallengeIDs []string   `json:"challengeIDs"`
	ExpiresAt    time.Time  `json:"expiresAt"`
	CreatedAt    time.Time  `json:"createdAt"`
}

// Challenge is an Internal Challenge.
type Challenge struct {
	ID              string        `json:"id"`
	AccountID       string        `json:"accountID"`
	AuthorizationID string        `json:"authorizationID"`
	Type            ChallengeType `json:"type"`
	Token           string        `json:"token"`
	// Host is the name acme-proxy fetches the token from: the Identifier, or
	// the Wildcard Base for a wildcard Identifier.
	Host        string     `json:"host"`
	Status      Status     `json:"status"`
	ValidatedAt *time.Time `json:"validatedAt,omitempty"`
	Error       *Problem   `json:"error,omitempty"`
}

// Certificate is the chain the Public CA issued for exactly one Internal Order.
type Certificate struct {
	ID        string    `json:"id"`
	AccountID string    `json:"accountID"`
	OrderID   string    `json:"orderID"`
	Serial    string    `json:"serial"` // lower-case hex
	ChainPEM  []byte    `json:"chainPEM"`
	Revoked   bool      `json:"revoked"`
	CreatedAt time.Time `json:"createdAt"`
}
