package acme

import (
	"fmt"
	"strings"
	"time"
)

// Config configures the Internal side of one acme-proxy instance.
type Config struct {
	// InternalDomain is the single domain this instance serves, e.g. "example.biz".
	InternalDomain string
	// WildcardBases are names inside the Internal Domain (never the Internal
	// Domain itself) under which wildcard Identifiers are allowed.
	WildcardBases []string
	// DatabasePath is the SQLite database file.
	DatabasePath string
	// OrderLifetime is how long an Internal Order and its Internal
	// Authorizations stay usable before they expire. Default 24h.
	OrderLifetime time.Duration
	// ChallengeTimeout bounds one HTTP-01 Internal Challenge attempt. Default 10s.
	ChallengeTimeout time.Duration
	// PublicOrderTimeout bounds one call to PublicCA.Issue. Default 10m.
	PublicOrderTimeout time.Duration
}

const (
	defaultOrderLifetime      = 24 * time.Hour
	defaultChallengeTimeout   = 10 * time.Second
	defaultPublicOrderTimeout = 10 * time.Minute
)

func normalizeName(n string) string {
	return strings.TrimSuffix(strings.ToLower(strings.TrimSpace(n)), ".")
}

// withDefaults returns a normalised copy of c with defaults filled in.
func (c Config) withDefaults() Config {
	c.InternalDomain = normalizeName(c.InternalDomain)
	bases := make([]string, 0, len(c.WildcardBases))
	for _, b := range c.WildcardBases {
		if b = normalizeName(b); b != "" {
			bases = append(bases, b)
		}
	}
	c.WildcardBases = bases
	if c.OrderLifetime <= 0 {
		c.OrderLifetime = defaultOrderLifetime
	}
	if c.ChallengeTimeout <= 0 {
		c.ChallengeTimeout = defaultChallengeTimeout
	}
	if c.PublicOrderTimeout <= 0 {
		c.PublicOrderTimeout = defaultPublicOrderTimeout
	}
	return c
}

// Validate reports configuration errors that must stop acme-proxy from starting.
func (c Config) Validate() error {
	c = c.withDefaults()
	if c.InternalDomain == "" {
		return fmt.Errorf("internal domain must be set")
	}
	if err := validateDNSName(c.InternalDomain); err != nil {
		return fmt.Errorf("internal domain %q: %v", c.InternalDomain, err)
	}
	for _, b := range c.WildcardBases {
		if b == c.InternalDomain {
			return fmt.Errorf("wildcard base %q must not be the internal domain itself: a certificate for *.%s would cover every internal host", b, b)
		}
		if !strings.HasSuffix(b, "."+c.InternalDomain) {
			return fmt.Errorf("wildcard base %q is not inside the internal domain %q", b, c.InternalDomain)
		}
		if err := validateDNSName(b); err != nil {
			return fmt.Errorf("wildcard base %q: %v", b, err)
		}
	}
	if c.DatabasePath == "" {
		return fmt.Errorf("database path must be set")
	}
	return nil
}

// validateDNSName checks that n is a syntactically valid, lower-case,
// non-wildcard DNS name with at least two labels.
func validateDNSName(n string) error {
	if len(n) == 0 || len(n) > 253 {
		return fmt.Errorf("invalid length")
	}
	labels := strings.Split(n, ".")
	if len(labels) < 2 {
		return fmt.Errorf("must have at least two labels")
	}
	for _, l := range labels {
		if len(l) == 0 || len(l) > 63 {
			return fmt.Errorf("invalid label length")
		}
		if l[0] == '-' || l[len(l)-1] == '-' {
			return fmt.Errorf("label %q starts or ends with a hyphen", l)
		}
		for _, r := range l {
			if !(r >= 'a' && r <= 'z' || r >= '0' && r <= '9' || r == '-') {
				return fmt.Errorf("label %q contains invalid character %q", l, r)
			}
		}
	}
	return nil
}
