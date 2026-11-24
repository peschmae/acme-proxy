package acme

import (
	"encoding/json"
	"errors"
	"fmt"
	"net/http"
	"strings"
)

const problemPrefix = "urn:ietf:params:acme:error:"

// Problem is an RFC 7807 problem document as used by ACME (RFC 8555 §6.7).
// It is used both for errors acme-proxy raises itself and for errors passed
// through unchanged from the Public CA.
type Problem struct {
	Type        string      `json:"type"`
	Detail      string      `json:"detail,omitempty"`
	Status      int         `json:"status,omitempty"`
	Identifier  *Identifier `json:"identifier,omitempty"`
	Subproblems []*Problem  `json:"subproblems,omitempty"`
}

// NewProblem builds a Problem. Short ACME error names such as "malformed"
// are expanded to their full URN.
func NewProblem(status int, typ, format string, args ...any) *Problem {
	if !strings.Contains(typ, ":") {
		typ = problemPrefix + typ
	}
	return &Problem{Type: typ, Status: status, Detail: fmt.Sprintf(format, args...)}
}

func (p *Problem) Error() string {
	return fmt.Sprintf("%s: %s", strings.TrimPrefix(p.Type, problemPrefix), p.Detail)
}

func malformed(format string, args ...any) *Problem {
	return NewProblem(http.StatusBadRequest, "malformed", format, args...)
}

func unauthorized(format string, args ...any) *Problem {
	return NewProblem(http.StatusForbidden, "unauthorized", format, args...)
}

func notFound(format string, args ...any) *Problem {
	return NewProblem(http.StatusNotFound, "malformed", format, args...)
}

func serverInternal(format string, args ...any) *Problem {
	return NewProblem(http.StatusInternalServerError, "serverInternal", format, args...)
}

// asProblem converts any error into a Problem. Problems (also wrapped ones)
// are returned as-is; anything else becomes serverInternal.
func asProblem(err error) *Problem {
	var p *Problem
	if errors.As(err, &p) {
		return p
	}
	return serverInternal("%v", err)
}

func writeProblem(w http.ResponseWriter, err error) {
	p := asProblem(err)
	status := p.Status
	if status == 0 {
		status = http.StatusInternalServerError
	}
	w.Header().Set("Content-Type", "application/problem+json")
	w.WriteHeader(status)
	_ = json.NewEncoder(w).Encode(p)
}
