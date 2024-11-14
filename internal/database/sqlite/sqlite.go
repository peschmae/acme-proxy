package sqlite

import (
	"database/sql"
	"encoding/base64"

	_ "github.com/mattn/go-sqlite3"
	"github.com/peschmae/acmepipe/pkg/database"
	"github.com/pkg/errors"
	"go.step.sm/crypto/randutil"
)

var (
	accountTable       = []byte("acme_account")
	orderTable         = []byte("acme_order")
	challengeTable     = []byte("acme_challenge")
	certTable          = []byte("acme_cert")
	nonceTable         = []byte("acme_nonce")
	authorizationTable = []byte("acme_authorization")
)

func NewSqliteDB() (database.Acme, error) {
	db, err := sql.Open("sqlite3", "./acme.db")
	if err != nil {
		panic(err)
	}

	sqlite := &DB{db: db}
	if err != nil {
		return nil, err
	}

	return sqlite, nil
}

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

func (db *DB) GetAccount() error {
	return nil
}

func (db *DB) UpdateAccount() error {

	return nil
}

func (db *DB) GetAccountByKey() error {
	return nil
}

func (db *DB) CreateOrder() error {
	return nil
}

func (db *DB) GetOrder() error {
	return nil
}

func (db *DB) UpdateOrder() error {
	return nil
}

func (db *DB) GetOrdersByAccountID() error {
	return nil
}

func (db *DB) CreateChallenge() error {
	return nil
}

func (db *DB) GetChallenge() error {
	return nil
}

func (db *DB) UpdateChallenge() error {
	return nil
}

func (db *DB) CreateCert() error {
	return nil
}

func (db *DB) GetCert() error {
	return nil
}

func (db *DB) GetCertBySerial() error {
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
		return database.ErrNotFound
	}
	return nil
}

func (db *DB) CreateAuthorization() error {
	return nil
}

func (db *DB) GetAuthorization() error {
	return nil
}

func (db *DB) UpdateAuthorization() error {
	return nil
}

func (db *DB) GetAuthorizationsByAccountID() error {
	return nil
}
