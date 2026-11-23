package acme

import (
	"database/sql"
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"time"

	_ "github.com/mattn/go-sqlite3"
	"go.step.sm/crypto/randutil"
)

// ErrNotFound is returned by the store when a resource does not exist.
var ErrNotFound = errors.New("not found")

const (
	tableAccounts       = "accounts"
	tableOrders         = "orders"
	tableAuthorizations = "authorizations"
	tableChallenges     = "challenges"
	tableCertificates   = "certificates"
)

// store persists acme-proxy's state in SQLite. Each resource is stored as a
// JSON document keyed by its ID. One store (one connection) is shared by the
// whole process.
type store struct {
	db *sql.DB
}

func openStore(path string) (*store, error) {
	db, err := sql.Open("sqlite3", fmt.Sprintf("file:%s?_busy_timeout=5000&_journal_mode=WAL&_foreign_keys=on", path))
	if err != nil {
		return nil, fmt.Errorf("opening database %q: %w", path, err)
	}
	// SQLite allows a single writer; serialise access through one connection.
	db.SetMaxOpenConns(1)

	for _, t := range []string{tableAccounts, tableOrders, tableAuthorizations, tableChallenges, tableCertificates} {
		if _, err := db.Exec(`CREATE TABLE IF NOT EXISTS ` + t + ` (id TEXT PRIMARY KEY, value TEXT NOT NULL)`); err != nil {
			db.Close()
			return nil, fmt.Errorf("creating table %s: %w", t, err)
		}
	}
	if _, err := db.Exec(`CREATE TABLE IF NOT EXISTS nonces (id TEXT PRIMARY KEY, created_at INTEGER NOT NULL)`); err != nil {
		db.Close()
		return nil, fmt.Errorf("creating table nonces: %w", err)
	}
	return &store{db: db}, nil
}

func (s *store) Close() error { return s.db.Close() }

func newID() (string, error) {
	return randutil.Alphanumeric(32)
}

func (s *store) put(table, id string, v any) error {
	j, err := json.Marshal(v)
	if err != nil {
		return fmt.Errorf("marshaling %s %s: %w", table, id, err)
	}
	_, err = s.db.Exec(`INSERT INTO `+table+` (id, value) VALUES (?, ?) ON CONFLICT(id) DO UPDATE SET value = excluded.value`, id, string(j))
	if err != nil {
		return fmt.Errorf("storing %s %s: %w", table, id, err)
	}
	return nil
}

func (s *store) get(table, id string, v any) error {
	var j string
	err := s.db.QueryRow(`SELECT value FROM `+table+` WHERE id = ?`, id).Scan(&j)
	if errors.Is(err, sql.ErrNoRows) {
		return ErrNotFound
	}
	if err != nil {
		return fmt.Errorf("loading %s %s: %w", table, id, err)
	}
	return json.Unmarshal([]byte(j), v)
}

// findBy returns the JSON documents of table whose top-level field equals value.
func (s *store) findBy(table, field string, value any) ([]string, error) {
	rows, err := s.db.Query(`SELECT value FROM `+table+` WHERE json_extract(value, '$.' || ?) = ? ORDER BY rowid`, field, value)
	if err != nil {
		return nil, fmt.Errorf("querying %s by %s: %w", table, field, err)
	}
	defer rows.Close()
	var out []string
	for rows.Next() {
		var j string
		if err := rows.Scan(&j); err != nil {
			return nil, err
		}
		out = append(out, j)
	}
	return out, rows.Err()
}

func findAll[T any](s *store, table, field string, value any) ([]*T, error) {
	docs, err := s.findBy(table, field, value)
	if err != nil {
		return nil, err
	}
	out := make([]*T, 0, len(docs))
	for _, d := range docs {
		v := new(T)
		if err := json.Unmarshal([]byte(d), v); err != nil {
			return nil, err
		}
		out = append(out, v)
	}
	return out, nil
}

// Accounts

func (s *store) CreateAccount(a *Account) error {
	id, err := newID()
	if err != nil {
		return err
	}
	a.ID = id
	return s.put(tableAccounts, a.ID, a)
}

func (s *store) UpdateAccount(a *Account) error { return s.put(tableAccounts, a.ID, a) }

func (s *store) GetAccount(id string) (*Account, error) {
	a := new(Account)
	if err := s.get(tableAccounts, id, a); err != nil {
		return nil, err
	}
	return a, nil
}

func (s *store) GetAccountByKeyID(keyID string) (*Account, error) {
	accs, err := findAll[Account](s, tableAccounts, "keyID", keyID)
	if err != nil {
		return nil, err
	}
	if len(accs) == 0 {
		return nil, ErrNotFound
	}
	return accs[0], nil
}

// Orders

func (s *store) CreateOrder(o *Order) error {
	id, err := newID()
	if err != nil {
		return err
	}
	o.ID = id
	return s.put(tableOrders, o.ID, o)
}

func (s *store) UpdateOrder(o *Order) error { return s.put(tableOrders, o.ID, o) }

func (s *store) GetOrder(id string) (*Order, error) {
	o := new(Order)
	if err := s.get(tableOrders, id, o); err != nil {
		return nil, err
	}
	return o, nil
}

func (s *store) GetOrdersByAccountID(accountID string) ([]*Order, error) {
	return findAll[Order](s, tableOrders, "accountID", accountID)
}

func (s *store) GetOrdersByStatus(st Status) ([]*Order, error) {
	return findAll[Order](s, tableOrders, "status", string(st))
}

// Authorizations

func (s *store) CreateAuthorization(az *Authorization) error {
	id, err := newID()
	if err != nil {
		return err
	}
	az.ID = id
	return s.put(tableAuthorizations, az.ID, az)
}

func (s *store) UpdateAuthorization(az *Authorization) error {
	return s.put(tableAuthorizations, az.ID, az)
}

func (s *store) GetAuthorization(id string) (*Authorization, error) {
	az := new(Authorization)
	if err := s.get(tableAuthorizations, id, az); err != nil {
		return nil, err
	}
	return az, nil
}

// Challenges

func (s *store) CreateChallenge(ch *Challenge) error {
	id, err := newID()
	if err != nil {
		return err
	}
	ch.ID = id
	return s.put(tableChallenges, ch.ID, ch)
}

func (s *store) UpdateChallenge(ch *Challenge) error { return s.put(tableChallenges, ch.ID, ch) }

func (s *store) GetChallenge(id string) (*Challenge, error) {
	ch := new(Challenge)
	if err := s.get(tableChallenges, id, ch); err != nil {
		return nil, err
	}
	return ch, nil
}

// Certificates

func (s *store) CreateCertificate(c *Certificate) error {
	id, err := newID()
	if err != nil {
		return err
	}
	c.ID = id
	return s.put(tableCertificates, c.ID, c)
}

func (s *store) UpdateCertificate(c *Certificate) error { return s.put(tableCertificates, c.ID, c) }

func (s *store) GetCertificate(id string) (*Certificate, error) {
	c := new(Certificate)
	if err := s.get(tableCertificates, id, c); err != nil {
		return nil, err
	}
	return c, nil
}

func (s *store) GetCertificateBySerial(serial string) (*Certificate, error) {
	certs, err := findAll[Certificate](s, tableCertificates, "serial", serial)
	if err != nil {
		return nil, err
	}
	if len(certs) == 0 {
		return nil, ErrNotFound
	}
	return certs[0], nil
}

// Nonces

const nonceLifetime = time.Hour

func (s *store) CreateNonce() (string, error) {
	raw, err := randutil.Alphanumeric(32)
	if err != nil {
		return "", err
	}
	nonce := base64.RawURLEncoding.EncodeToString([]byte(raw))
	now := time.Now()
	if _, err := s.db.Exec(`INSERT INTO nonces (id, created_at) VALUES (?, ?)`, nonce, now.Unix()); err != nil {
		return "", fmt.Errorf("storing nonce: %w", err)
	}
	// Opportunistically drop stale nonces.
	_, _ = s.db.Exec(`DELETE FROM nonces WHERE created_at < ?`, now.Add(-nonceLifetime).Unix())
	return nonce, nil
}

// ConsumeNonce deletes the nonce, returning ErrNotFound if it was unknown,
// already used or expired.
func (s *store) ConsumeNonce(nonce string) error {
	res, err := s.db.Exec(`DELETE FROM nonces WHERE id = ? AND created_at >= ?`, nonce, time.Now().Add(-nonceLifetime).Unix())
	if err != nil {
		return fmt.Errorf("consuming nonce: %w", err)
	}
	if n, err := res.RowsAffected(); err != nil || n == 0 {
		return ErrNotFound
	}
	return nil
}
