package acme

import (
	"time"

	_ "github.com/mattn/go-sqlite3"

	"github.com/pkg/errors"
	"go.step.sm/crypto/jose"
)

// dbAccount represents an ACME account.
type dbAccount struct {
	ID             string           `json:"id"`
	KeyId          string           `json:"kid"`
	Key            *jose.JSONWebKey `json:"key"`
	Contact        []string         `json:"contact,omitempty"`
	Status         Status           `json:"status"`
	LocationPrefix string           `json:"locationPrefix"`
	CreatedAt      time.Time        `json:"createdAt"`
	DeactivatedAt  time.Time        `json:"deactivatedAt"`
}

type dbOrder struct {
	ID               string       `json:"id"`
	AccountID        string       `json:"accountID"`
	Identifiers      []Identifier `json:"identifiers"`
	AuthorizationIDs []string     `json:"authorizationIDs"`
	Status           Status       `json:"status"`
	NotBefore        time.Time    `json:"notBefore,omitempty"`
	NotAfter         time.Time    `json:"notAfter,omitempty"`
	CreatedAt        time.Time    `json:"createdAt"`
	ExpiresAt        time.Time    `json:"expiresAt,omitempty"`
	CertificateID    string       `json:"certificate,omitempty"`
	Error            *AcmeError   `json:"error,omitempty"`
}

// dbAuthz is the base authz type that others build from.
type dbAuthz struct {
	ID           string     `json:"id"`
	AccountID    string     `json:"accountID"`
	Identifier   Identifier `json:"identifier"`
	Status       Status     `json:"status"`
	Token        string     `json:"token"`
	Fingerprint  string     `json:"fingerprint,omitempty"`
	ChallengeIDs []string   `json:"challengeIDs"`
	Wildcard     bool       `json:"wildcard"`
	CreatedAt    time.Time  `json:"createdAt"`
	ExpiresAt    time.Time  `json:"expiresAt"`
	Error        *AcmeError `json:"error"`
}

type dbChallenge struct {
	ID          string        `json:"id"`
	AccountID   string        `json:"accountID"`
	Type        ChallengeType `json:"type"`
	Status      Status        `json:"status"`
	Token       string        `json:"token"`
	Value       string        `json:"value"`
	Target      string        `json:"target,omitempty"`
	ValidatedAt time.Time     `json:"validatedAt"`
	CreatedAt   time.Time     `json:"createdAt"`
	Error       *AcmeError    `json:"error"` // TODO(hs): a bit dangerous; should become db-specific type
}

// ErrNotFound is returned when a requested resource is not found
var ErrNotFound = errors.New("not found")

type Database interface {
	CreateTables() error

	CreateAccount(*Account) error
	GetAccount(string) (*Account, error)
	UpdateAccount(*Account) error
	GetAccountByKeyID(string) (*Account, error)

	CreateOrder(*Order) error
	GetOrder(string) (*Order, error)
	UpdateOrder(*Order) error
	GetOrdersByAccountID(string) ([]*Order, error)

	CreateChallenge(*Challenge) error
	GetChallenge(string) (*Challenge, error)
	UpdateChallenge(*Challenge) error

	CreateCert(*Certificate) error
	GetCert(string) (*Certificate, error)
	GetCertBySerial(string) (*Certificate, error)

	CreateNonce() (string, error)
	DeleteNonce(string) error

	CreateAuthorization(*Authorization) error
	GetAuthorization(string) (*Authorization, error)
	UpdateAuthorization(*Authorization) error
	GetAuthorizationsByAccountID(string) error
}

var (
	accountTable       = []byte("acme_account")
	orderTable         = []byte("acme_order")
	challengeTable     = []byte("acme_challenge")
	certTable          = []byte("acme_cert")
	nonceTable         = []byte("acme_nonce")
	authorizationTable = []byte("acme_authorization")
)
