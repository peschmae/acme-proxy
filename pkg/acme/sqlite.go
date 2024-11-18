package acme

import (
	"database/sql"
	"encoding/base64"
	"time"

	_ "github.com/mattn/go-sqlite3"

	"github.com/pkg/errors"
	"go.step.sm/crypto/jose"
	"go.step.sm/crypto/randutil"
)

func NewSqliteDB() (Database, error) {
	db, err := sql.Open("sqlite3", "./acme.db")
	if err != nil {
		panic(err)
	}

	sqlite := &DB{db: db}

	return sqlite, nil
}

// dbAccount represents an ACME account.
type dbAccount struct {
	ID              string           `json:"id"`
	Key             *jose.JSONWebKey `json:"key"`
	Contact         []string         `json:"contact,omitempty"`
	Status          Status           `json:"status"`
	LocationPrefix  string           `json:"locationPrefix"`
	ProvisionerID   string           `json:"provisionerID,omitempty"`
	ProvisionerName string           `json:"provisionerName"`
	CreatedAt       time.Time        `json:"createdAt"`
	DeactivatedAt   time.Time        `json:"deactivatedAt"`
}

// ErrNotFound is returned when a requested resource is not found
var ErrNotFound = errors.New("not found")

type Database interface {
	CreateTables() error

	CreateAccount() error
	GetAccount(string) (*Account, error)
	UpdateAccount() error
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

// implements database.Database
type DB struct {
	db *sql.DB
}

func (db *DB) CreateTables() error {

	tables := [][]byte{
		accountTable,
		orderTable,
		challengeTable,
		certTable,
		nonceTable,
		authorizationTable,
	}

	for _, t := range tables {
		_, err := db.db.Exec(`CREATE TABLE IF NOT EXISTS ` + string(t) + ` (
			id INTEGER PRIMARY KEY AUTOINCREMENT,
			value JSONB,
			created_at DATETIME DEFAULT CURRENT_TIMESTAMP,
			updated_at DATETIME DEFAULT CURRENT_TIMESTAMP
		)`)
		if err != nil {
			return err
		}
	}

	return nil

}

func (db *DB) Close() error {
	return db.db.Close()
}

func (db *DB) CreateAccount() error {
	return nil
}

func (db *DB) GetAccount(_ string) (*Account, error) {
	return nil, nil
}

func (db *DB) UpdateAccount() error {

	return nil
}

func (db *DB) GetAccountByKeyID(_ string) (*Account, error) {
	return nil, nil
}

func (db *DB) CreateOrder() error {
	return nil
}

func (db *DB) GetOrder(_ string) error {
	return nil
}

func (db *DB) UpdateOrder() error {
	return nil
}

func (db *DB) GetOrdersByAccountID(_ string) error {
	return nil
}

func (db *DB) CreateChallenge() error {
	return nil
}

func (db *DB) GetChallenge(_ string) error {
	return nil
}

func (db *DB) UpdateChallenge() error {
	return nil
}

func (db *DB) CreateCert() error {
	return nil
}

func (db *DB) GetCert(_ string) error {
	return nil
}

func (db *DB) GetCertBySerial(_ string) error {
	return nil
}

func (db *DB) CreateNonce() (string, error) {
	_id, err := randutil.Alphanumeric(32)
	if err != nil {
		return "", errors.Wrap(err, "error generating random alphanumeric ID")
	}
	id := base64.RawURLEncoding.EncodeToString([]byte(_id))

	_, err = db.db.Exec(`INSERT INTO `+string(nonceTable)+` (value) VALUES (?)`, id)

	if err != nil {
		return "", errors.Wrap(err, "error inserting nonce into database")
	}

	return id, nil
}

func (db *DB) DeleteNonce(nonce string) error {
	res, err := db.db.Exec(`DELETE FROM `+string(nonceTable)+` WHERE value = ?`, nonce)
	if err != nil {
		return errors.Wrap(err, "error deleting nonce from database")
	}
	if ok, err := res.RowsAffected(); err != nil || ok == 0 {
		return ErrNotFound
	}
	return nil
}

func (db *DB) CreateAuthorization() error {
	return nil
}

func (db *DB) GetAuthorization(_ string) error {
	return nil
}

func (db *DB) UpdateAuthorization() error {
	return nil
}

func (db *DB) GetAuthorizationsByAccountID(_ string) error {
	return nil
}
