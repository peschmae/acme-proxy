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

	j, err := json.Marshal(dbAcc)
	if err != nil {
		return AcmeError{http.StatusInternalServerError, "serverInternal", "error marshaling account"}

	}

	_, err = db.db.Exec(`INSERT INTO `+string(accountTable)+` (value) VALUES (?)`, j)

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

func (db *DB) CreateOrder(o *Order) error {
	var err error
	o.ID, err = randID()
	if err != nil {
		return err
	}

	now := time.Now()
	dbOrder := &dbOrder{
		ID:               o.ID,
		AccountID:        o.AccountID,
		Status:           o.Status,
		CreatedAt:        now,
		ExpiresAt:        o.ExpiresAt,
		Identifiers:      o.Identifiers,
		NotBefore:        o.NotBefore,
		NotAfter:         o.NotAfter,
		AuthorizationIDs: o.AuthorizationIDs,
	}

	j, err := json.Marshal(dbOrder)
	if err != nil {
		return AcmeError{http.StatusInternalServerError, "serverInternal", "error marshaling order"}

	}

	_, err = db.db.Exec(`INSERT INTO `+string(orderTable)+` (value) VALUES (?)`, j)

	return err
}

func (db *DB) GetOrder(orderID string) (*Order, error) {
	res := db.db.QueryRow(`SELECT value FROM `+string(orderTable)+` WHERE value->>'id' = ?`, orderID)

	var j []byte
	if err := res.Scan(&j); err != nil {
		return nil, ErrNotFound
	}

	var dbOrder dbOrder
	if err := json.Unmarshal(j, &dbOrder); err != nil {
		return nil, errors.Wrap(err, "error unmarshaling order from database")
	}

	order := &Order{
		ID:               dbOrder.ID,
		AccountID:        dbOrder.AccountID,
		Status:           dbOrder.Status,
		ExpiresAt:        dbOrder.ExpiresAt,
		Identifiers:      dbOrder.Identifiers,
		NotBefore:        dbOrder.NotBefore,
		NotAfter:         dbOrder.NotAfter,
		AuthorizationIDs: dbOrder.AuthorizationIDs,
	}

	return order, nil
}

func (db *DB) UpdateOrder(order *Order) error {

	dbOrder := &dbOrder{
		ID:               order.ID,
		AccountID:        order.AccountID,
		Status:           order.Status,
		ExpiresAt:        order.ExpiresAt,
		Identifiers:      order.Identifiers,
		NotBefore:        order.NotBefore,
		NotAfter:         order.NotAfter,
		AuthorizationIDs: order.AuthorizationIDs,
		CertificateID:    order.CertificateID,
	}

	j, err := json.Marshal(dbOrder)
	if err != nil {
		return AcmeError{http.StatusInternalServerError, "serverInternal", "error marshaling order"}

	}

	_, err = db.db.Exec(`UPDATE `+string(orderTable)+` set value = ? WHERE value->>'id' = ?`, j, order.ID)

	return err
}

func (db *DB) GetOrdersByAccountID(_ string) ([]*Order, error) {
	return nil, nil
}

func (db *DB) CreateChallenge(chall *Challenge) error {
	var err error
	chall.ID, err = randID()
	if err != nil {
		return err
	}

	dbChall := &dbChallenge{
		ID:        chall.ID,
		AccountID: chall.AccountID,
		Value:     chall.Value,
		Status:    StatusPending,
		Token:     chall.Token,
		CreatedAt: time.Now(),
		Type:      chall.Type,
		Target:    chall.Target,
	}

	j, err := json.Marshal(dbChall)
	if err != nil {
		return AcmeError{http.StatusInternalServerError, "serverInternal", "error marshaling challenge"}
	}

	_, err = db.db.Exec(`INSERT INTO `+string(challengeTable)+` (value) VALUES (?)`, j)

	return err
}

func (db *DB) GetChallenge(challId string) (*Challenge, error) {
	res := db.db.QueryRow(`SELECT value FROM `+string(challengeTable)+` WHERE value->>'id' = ?`, challId)

	var j []byte
	if err := res.Scan(&j); err != nil {
		return nil, ErrNotFound
	}

	var dbChall dbChallenge
	if err := json.Unmarshal(j, &dbChall); err != nil {
		return nil, AcmeError{http.StatusInternalServerError, "serverInternal", "error unmarshaling challenge from database"}
	}

	chall := &Challenge{
		ID:        dbChall.ID,
		AccountID: dbChall.AccountID,
		Value:     dbChall.Value,
		Status:    dbChall.Status,
		Token:     dbChall.Token,
		Type:      dbChall.Type,
		Target:    dbChall.Target,
	}

	return chall, nil
}

func (db *DB) UpdateChallenge(chall *Challenge) error {
	dbChall := &dbChallenge{
		ID:          chall.ID,
		AccountID:   chall.AccountID,
		Value:       chall.Value,
		Status:      chall.Status,
		Token:       chall.Token,
		ValidatedAt: chall.ValidatedAt,
		Type:        chall.Type,
		Target:      chall.Target,
	}

	j, err := json.Marshal(dbChall)
	if err != nil {
		return AcmeError{http.StatusInternalServerError, "serverInternal", "error marshaling challenge"}
	}

	_, err = db.db.Exec(`UPDATE `+string(challengeTable)+` SET value = ? WHERE value->>'id' = ?`, j, chall.ID)

	return err
}

func (db *DB) CreateCert(cert *Certificate) error {
	return nil
}

func (db *DB) GetCert(_ string) (*Certificate, error) {
	return nil, nil
}

func (db *DB) GetCertBySerial(_ string) (*Certificate, error) {
	return nil, nil
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

func (db *DB) CreateAuthorization(az *Authorization) error {
	var err error
	az.ID, err = randID()
	if err != nil {
		return err
	}

	chIDs := make([]string, len(az.Challenges))
	for i, ch := range az.Challenges {
		chIDs[i] = ch.ID
	}

	now := time.Now()
	dbAuthz := &dbAuthz{
		ID:           az.ID,
		AccountID:    az.AccountID,
		Status:       az.Status,
		CreatedAt:    now,
		ExpiresAt:    az.ExpiresAt,
		Identifier:   az.Identifier,
		ChallengeIDs: chIDs,
		Token:        az.Token,
		Fingerprint:  az.Fingerprint,
		Wildcard:     az.Wildcard,
	}

	j, err := json.Marshal(dbAuthz)
	if err != nil {
		return AcmeError{http.StatusInternalServerError, "serverInternal", "error marshaling authorization"}
	}

	_, err = db.db.Exec(`INSERT INTO `+string(authorizationTable)+` (value) VALUES (?)`, j)

	return err
}

func (db *DB) GetAuthorization(authzID string) (*Authorization, error) {
	res := db.db.QueryRow(`SELECT value FROM `+string(authorizationTable)+` WHERE value->>'id' = ?`, authzID)

	var j []byte
	if err := res.Scan(&j); err != nil {
		return nil, ErrNotFound
	}

	var dbAuthz dbAuthz
	if err := json.Unmarshal(j, &dbAuthz); err != nil {
		return nil, AcmeError{http.StatusInternalServerError, "serverInternal", "error unmarshaling authorization from database"}
	}

	az := &Authorization{
		ID:          dbAuthz.ID,
		AccountID:   dbAuthz.AccountID,
		Status:      dbAuthz.Status,
		ExpiresAt:   dbAuthz.ExpiresAt,
		Identifier:  dbAuthz.Identifier,
		Token:       dbAuthz.Token,
		Fingerprint: dbAuthz.Fingerprint,
		Wildcard:    dbAuthz.Wildcard,
		Challenges:  make([]*Challenge, len(dbAuthz.ChallengeIDs)),
	}

	for i, chID := range dbAuthz.ChallengeIDs {
		ch, err := db.GetChallenge(chID)
		if err != nil {
			return nil, AcmeError{http.StatusInternalServerError, "serverInternal", "error getting challenge"}
		}
		az.Challenges[i] = ch
	}

	return az, nil
}

func (db *DB) UpdateAuthorization(auth *Authorization) error {
	return nil
}

func (db *DB) GetAuthorizationsByAccountID(_ string) error {
	return nil
}
