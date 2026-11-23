package acme

import (
	"net/http"
	"strings"
)

// checkIdentifiers applies the Identifier policy (ADR-0002, ADR-0003) to the
// identifiers of a new Internal Order. It returns the normalised, de-duplicated
// identifiers, or a rejectedIdentifier problem with one subproblem per
// offending identifier.
func (s *Server) checkIdentifiers(ids []Identifier) ([]Identifier, error) {
	if len(ids) == 0 {
		return nil, malformed("identifiers list cannot be empty")
	}
	var (
		out  []Identifier
		seen = map[string]bool{}
		subs []*Problem
	)
	for _, id := range ids {
		orig := id
		if id.Type != IdentifierDNS {
			subs = append(subs, &Problem{
				Type:       problemPrefix + "rejectedIdentifier",
				Detail:     "only dns identifiers are supported",
				Identifier: &orig,
			})
			continue
		}
		value := normalizeName(id.Value)
		if reason := s.identifierRejection(value); reason != "" {
			subs = append(subs, &Problem{
				Type:       problemPrefix + "rejectedIdentifier",
				Detail:     reason,
				Identifier: &orig,
			})
			continue
		}
		if !seen[value] {
			seen[value] = true
			out = append(out, Identifier{Type: IdentifierDNS, Value: value})
		}
	}
	if len(subs) > 0 {
		p := NewProblem(http.StatusBadRequest, "rejectedIdentifier",
			"acme-proxy only issues certificates for names in %s", s.cfg.InternalDomain)
		p.Subproblems = subs
		return nil, p
	}
	return out, nil
}

// identifierRejection returns why a normalised DNS identifier value is not
// allowed, or "" if it is.
func (s *Server) identifierRejection(value string) string {
	domain := s.cfg.InternalDomain
	base, wildcard := strings.CutPrefix(value, "*.")
	if err := validateDNSName(base); err != nil {
		return "invalid DNS name: " + err.Error()
	}
	if base != domain && !strings.HasSuffix(base, "."+domain) {
		return "name is outside the internal domain " + domain
	}
	if !wildcard {
		return ""
	}
	if base == domain {
		return "a wildcard for the internal domain itself is never issued"
	}
	for _, b := range s.cfg.WildcardBases {
		if b == base {
			return ""
		}
	}
	return base + " is not a configured wildcard base"
}
