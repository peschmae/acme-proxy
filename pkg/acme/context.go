package acme

import (
	"context"
	"net/http"
	"net/url"
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

func newDatabase() (Database, error) {

	db, err := NewSqliteDB()
	if err != nil {
		return nil, err
	}
	db.CreateTables()

	return db, nil
}

type payloadKey struct{}

type Payload struct {
	Value []byte
	// Empty Body in a POST request, should just display the resource
	IsPostAsGet bool
	IsEmptyJSON bool
}

func payloadFromContext(ctx context.Context) *Payload {
	return ctx.Value(payloadKey{}).(*Payload)
}

type jwsContextKey struct{}

type jwkContextKey struct{}

type accContextKey struct{}
