package acme

import (
	"bytes"
	"context"
	"crypto/tls"
	"errors"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/url"
	"strings"
)

// validateHTTP01 performs one HTTP-01 Internal Challenge attempt
// (RFC 8555 §8.3) against ch.Host, returning nil on success or the problem
// to record on the challenge.
func (s *Server) validateHTTP01(ctx context.Context, ch *Challenge, accountKeyThumbprint string) *Problem {
	ctx, cancel := context.WithTimeout(ctx, s.cfg.ChallengeTimeout)
	defer cancel()

	expected := ch.Token + "." + accountKeyThumbprint
	target := (&url.URL{Scheme: "http", Host: ch.Host, Path: "/.well-known/acme-challenge/" + ch.Token}).String()

	client := &http.Client{
		Transport: &http.Transport{
			Proxy:       nil, // Internal Challenges always go over the internal network
			DialContext: s.dial,
			// Like public CAs, accept any certificate when a redirect leads to
			// https: the proof is the response body, not the TLS certificate.
			TLSClientConfig:   &tls.Config{InsecureSkipVerify: true}, //nolint:gosec
			DisableKeepAlives: true,
		},
		CheckRedirect: func(req *http.Request, via []*http.Request) error {
			if len(via) >= 10 {
				return errors.New("too many redirects")
			}
			if req.URL.Scheme != "http" && req.URL.Scheme != "https" {
				return fmt.Errorf("redirect to unsupported scheme %q", req.URL.Scheme)
			}
			if p := req.URL.Port(); p != "" && p != "80" && p != "443" {
				return fmt.Errorf("redirect to unsupported port %s", p)
			}
			return nil
		},
	}

	req, err := http.NewRequestWithContext(ctx, http.MethodGet, target, nil)
	if err != nil {
		return serverInternal("building challenge request: %v", err)
	}
	req.Header.Set("User-Agent", "acme-proxy")
	res, err := client.Do(req)
	if err != nil {
		var dnsErr *net.DNSError
		if errors.As(err, &dnsErr) {
			return NewProblem(http.StatusBadRequest, "dns", "resolving %s: %v", ch.Host, dnsErr)
		}
		return NewProblem(http.StatusBadRequest, "connection", "fetching %s: %v", target, err)
	}
	defer res.Body.Close()
	if res.StatusCode != http.StatusOK {
		return unauthorized("fetching %s: unexpected HTTP status %d", target, res.StatusCode)
	}
	body, err := io.ReadAll(io.LimitReader(res.Body, 1024))
	if err != nil {
		return NewProblem(http.StatusBadRequest, "connection", "reading response from %s: %v", target, err)
	}
	if got := string(bytes.TrimSpace(body)); got != expected {
		return NewProblem(http.StatusBadRequest, "incorrectResponse",
			"key authorization from %s does not match: got %q", target, truncate(got, 128))
	}
	return nil
}

func truncate(s string, n int) string {
	if len(s) <= n {
		return s
	}
	return s[:n] + "…"
}

// NewChallengeDialer returns a dialer for Internal Challenges. With an empty
// resolver it uses the system resolver; otherwise it resolves names through
// the given DNS server ("host:port").
func NewChallengeDialer(resolver string) func(ctx context.Context, network, addr string) (net.Conn, error) {
	d := &net.Dialer{}
	if resolver = strings.TrimSpace(resolver); resolver != "" {
		d.Resolver = &net.Resolver{
			PreferGo: true,
			Dial: func(ctx context.Context, network, _ string) (net.Conn, error) {
				return (&net.Dialer{}).DialContext(ctx, network, resolver)
			},
		}
	}
	return d.DialContext
}
