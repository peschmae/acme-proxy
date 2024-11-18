package acme

import (
	"context"
	"fmt"
	"net/http"
	"time"

	"go.step.sm/crypto/randutil"
)

// Authorization representst an ACME Authorization.
type Authorization struct {
	ID          string       `json:"-"`
	AccountID   string       `json:"-"`
	Token       string       `json:"-"`
	Fingerprint string       `json:"-"`
	Identifier  Identifier   `json:"identifier"`
	Status      Status       `json:"status"`
	Challenges  []*Challenge `json:"challenges"`
	Wildcard    bool         `json:"wildcard"`
	ExpiresAt   time.Time    `json:"expires"`
	Error       *AcmeError   `json:"error,omitempty"`
}

// UpdateStatus updates the ACME Authorization Status if necessary.
// Changes to the Authorization are saved using the database interface.
func (az *Authorization) UpdateStatus(ctx context.Context, db DB) error {
	now := time.Now()

	switch az.Status {
	case StatusInvalid:
		return nil
	case StatusValid:
		return nil
	case StatusPending:
		// check expiry
		if now.After(az.ExpiresAt) {
			az.Status = StatusInvalid
			break
		}

		var isValid = false
		for _, ch := range az.Challenges {
			if ch.Status == StatusValid {
				isValid = true
				break
			}
		}

		if !isValid {
			return nil
		}
		az.Status = StatusValid
		az.Error = nil
	default:
		return AcmeError{http.StatusInternalServerError, "serverInternal", fmt.Sprintf("unrecognized authorization status %s", az.Status)}
	}

	if err := db.UpdateAuthorization(az); err != nil {
		return AcmeError{http.StatusInternalServerError, "serverInternal", "error updating authorization"}
	}
	return nil
}

func newAuthorization(ctx context.Context, az *Authorization) error {
	value, isWildcard := trimIfWildcard(az.Identifier.Value)
	az.Wildcard = isWildcard
	az.Identifier = Identifier{
		Value: value,
		Type:  az.Identifier.Type,
	}

	chTypes := challengeTypes(az)

	var err error
	az.Token, err = randutil.Alphanumeric(32)
	if err != nil {
		return AcmeError{http.StatusInternalServerError, "serverInternal", "error generating random alphanumeric ID"}
	}

	db := ctx.Value(dbKey{}).(DB)

	az.Challenges = make([]*Challenge, 0, len(chTypes))
	for _, typ := range chTypes {

		ch := &Challenge{
			AccountID: az.AccountID,
			Value:     az.Identifier.Value,
			Type:      typ,
			Token:     az.Token,
			Status:    StatusPending,
		}
		if err := db.CreateChallenge(ch); err != nil {
			return AcmeError{http.StatusInternalServerError, "serverInternal", "error creating challenge"}
		}
		az.Challenges = append(az.Challenges, ch)
	}
	if err = db.CreateAuthorization(az); err != nil {
		return AcmeError{http.StatusInternalServerError, "serverInternal", "error creating authorization"}
	}
	return nil
}

// challengeTypes determines the types of challenges that should be used
// for the ACME authorization request.
func challengeTypes(az *Authorization) []ChallengeType {
	var chTypes []ChallengeType

	switch az.Identifier.Type {
	case IP:
		chTypes = []ChallengeType{HTTP01}
	case DNS:
		chTypes = []ChallengeType{DNS01}
		// HTTP and TLS challenges can only be used for identifiers without wildcards.
		if !az.Wildcard {
			chTypes = append(chTypes, []ChallengeType{HTTP01}...)
		}
	default:
		chTypes = []ChallengeType{}
	}

	return chTypes
}
