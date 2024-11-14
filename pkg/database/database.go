package database

import (
	"errors"
)

// ErrNotFound is returned when a requested resource is not found
var ErrNotFound = errors.New("not found")

type Acme interface {
	CreateTables() error

	CreateAccount() error
	GetAccount() error
	UpdateAccount() error
	GetAccountByKey() error

	CreateOrder() error
	GetOrder() error
	UpdateOrder() error
	GetOrdersByAccountID() error

	CreateChallenge() error
	GetChallenge() error
	UpdateChallenge() error

	CreateCert() error
	GetCert() error
	GetCertBySerial() error

	CreateNonce() (string, error)
	DeleteNonce(string) error

	CreateAuthorization() error
	GetAuthorization() error
	UpdateAuthorization() error
	GetAuthorizationsByAccountID() error
}
