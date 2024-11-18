package acme

import (
	"database/sql"
	"encoding/base64"
	"encoding/json"
	"net/http"
	"time"

	_ "github.com/mattn/go-sqlite3"

	"github.com/pkg/errors"
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

func randID() (val string, err error) {
	val, err = randutil.Alphanumeric(32)
	if err != nil {
		return "", errors.Wrap(err, "error generating random alphanumeric ID")
	}
	return val, nil
}

func (db *DB) CreateAccount(acc *Account) error {

	var err error
	acc.ID, err = randID()
	if err != nil {
		return AcmeError{http.StatusInternalServerError, "serverInternal", "error generating random ID"}
	}

	dbAcc := &dbAccount{
		ID:             acc.ID,
		Key:            acc.Key,
		Contact:        acc.Contact,
		Status:         acc.Status,
		LocationPrefix: acc.LocationPrefix,
		CreatedAt:      time.Now(),
	}

	dbAcc.KeyId, err = KeyToID(acc.Key)
	if err != nil {
		return AcmeError{http.StatusInternalServerError, "serverInternal", "error generating key ID"}
	}

	json, err := json.Marshal(dbAcc)
	if err != nil {
		return AcmeError{http.StatusInternalServerError, "serverInternal", "error marshaling account"}

	}

	_, err = db.db.Exec(`INSERT INTO `+string(accountTable)+` (value) VALUES (?)`, json)

	return err
}

func (db *DB) GetAccount(accID string) (*Account, error) {
	res := db.db.QueryRow(`SELECT value FROM `+string(accountTable)+` WHERE value->>'id' = ?`, accID)

	var j []byte
	if err := res.Scan(&j); err != nil {
		return nil, ErrNotFound
	}

	var dbAcc dbAccount
	if err := json.Unmarshal(j, &dbAcc); err != nil {
		return nil, errors.Wrap(err, "error unmarshaling account from database")
	}

	acc := &Account{
		ID:             dbAcc.ID,
		Key:            dbAcc.Key,
		Contact:        dbAcc.Contact,
		Status:         dbAcc.Status,
		LocationPrefix: dbAcc.LocationPrefix,
	}

	return acc, nil
}

func (db *DB) UpdateAccount(acc *Account) error {

	return nil
}

func (db *DB) GetAccountByKeyID(keyID string) (*Account, error) {

	return db.GetAccount(keyID)
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
