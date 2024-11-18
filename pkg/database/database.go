package database

import (
	"errors"
)

// ErrNotFound is returned when a requested resource is not found
var ErrNotFound = errors.New("not found")

type Acme interface {
	CreateTables() error

	CreateAccount() error
	GetAccount(string) (any, error)
	UpdateAccount() error
	GetAccountByKeyID(string) (any, error)

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
