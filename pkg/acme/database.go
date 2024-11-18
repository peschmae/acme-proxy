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

// ErrNotFound is returned when a requested resource is not found
var ErrNotFound = errors.New("not found")

type Database interface {
	CreateTables() error

	CreateAccount(*Account) error
	GetAccount(string) (*Account, error)
	UpdateAccount(*Account) error
	GetAccountByKeyID(string) (*Account, error)

	CreateOrder() error
	GetOrder(string) error
	UpdateOrder() error
	GetOrdersByAccountID(string) error

	CreateChallenge() error
	GetChallenge(string) error
	UpdateChallenge() error

	CreateCert() error
	GetCert(string) error
	GetCertBySerial(string) error

	CreateNonce() (string, error)
	DeleteNonce(string) error

	CreateAuthorization() error
	GetAuthorization(string) error
	UpdateAuthorization() error
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
