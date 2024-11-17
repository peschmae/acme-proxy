package acme

import (
	"context"
	"net/http"
	"net/url"

	"github.com/peschmae/acmepipe/internal/database/sqlite"
	"github.com/peschmae/acmepipe/pkg/database"
)

type baseUrlKey struct{}

func newBaseURLContext(ctx context.Context, r *http.Request) context.Context {
	var u *url.URL
	if r.Host != "" {
		u = &url.URL{Host: r.Host}
	}
	if r.TLS != nil {
		u.Scheme = "https"
	} else {
		u.Scheme = "http"
	}
	u.Path = prefix

	return context.WithValue(ctx, baseUrlKey{}, u)
}

type dbKey struct{}

func newDBContext(ctx context.Context) context.Context {
	db, err := newDatabase()
	if err != nil {
		panic(err)
	}
	return context.WithValue(ctx, dbKey{}, db)
}

func newDatabase() (database.Acme, error) {

	db, err := sqlite.NewSqliteDB()
	if err != nil {
		return nil, err
	}
	db.CreateTables()

	return db, nil
}
