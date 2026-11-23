package acme

import (
	"encoding/json"
	"errors"
	"net/http"
	"time"

	"github.com/go-chi/chi/v5"
	"go.step.sm/crypto/randutil"
)

type challengeResponse struct {
	Type      ChallengeType `json:"type"`
	URL       string        `json:"url"`
	Token     string        `json:"token"`
	Status    Status        `json:"status"`
	Validated string        `json:"validated,omitempty"`
	Error     *Problem      `json:"error,omitempty"`
}

func renderChallenge(r *http.Request, ch *Challenge) challengeResponse {
	resp := challengeResponse{
		Type:   ch.Type,
		URL:    linkURL(r, "challenge", ch.ID),
		Token:  ch.Token,
		Status: ch.Status,
		Error:  ch.Error,
	}
	if ch.ValidatedAt != nil {
		resp.Validated = ch.ValidatedAt.UTC().Format(time.RFC3339)
	}
	return resp
}

type authorizationResponse struct {
	Identifier Identifier          `json:"identifier"`
	Status     Status              `json:"status"`
	Expires    string              `json:"expires"`
	Challenges []challengeResponse `json:"challenges"`
	Wildcard   bool                `json:"wildcard,omitempty"`
}

// newAuthorization creates a fresh Internal Authorization with one http-01
// Internal Challenge. For "*.base" the authorization is for "base" with
// wildcard=true, and the challenge is fetched from the Wildcard Base host.
func (s *Server) newAuthorization(acc *Account, orderID string, id Identifier, expires time.Time) (*Authorization, error) {
	base, wildcard := cutWildcard(id.Value)
	az := &Authorization{
		AccountID:  acc.ID,
		OrderID:    orderID,
		Identifier: Identifier{Type: IdentifierDNS, Value: base},
		Wildcard:   wildcard,
		Status:     StatusPending,
		ExpiresAt:  expires,
		CreatedAt:  time.Now(),
	}
	if err := s.store.CreateAuthorization(az); err != nil {
		return nil, err
	}
	token, err := randutil.Alphanumeric(43)
	if err != nil {
		return nil, err
	}
	ch := &Challenge{
		AccountID:       acc.ID,
		AuthorizationID: az.ID,
		Type:            ChallengeHTTP01,
		Token:           token,
		Host:            base,
		Status:          StatusPending,
	}
	if err := s.store.CreateChallenge(ch); err != nil {
		return nil, err
	}
	az.ChallengeIDs = []string{ch.ID}
	if err := s.store.UpdateAuthorization(az); err != nil {
		return nil, err
	}
	return az, nil
}

func cutWildcard(v string) (string, bool) {
	if len(v) > 2 && v[:2] == "*." {
		return v[2:], true
	}
	return v, false
}

// refreshAuthorization applies expiry and challenge results to a pending
// authorization and persists any change. Callers hold s.mu.
func (s *Server) refreshAuthorization(az *Authorization) ([]*Challenge, error) {
	chs := make([]*Challenge, 0, len(az.ChallengeIDs))
	for _, id := range az.ChallengeIDs {
		ch, err := s.store.GetChallenge(id)
		if err != nil {
			return nil, err
		}
		chs = append(chs, ch)
	}
	if az.Status != StatusPending {
		return chs, nil
	}
	switch {
	case time.Now().After(az.ExpiresAt):
		az.Status = StatusInvalid
	case anyChallenge(chs, StatusValid):
		az.Status = StatusValid
	case allChallenges(chs, StatusInvalid):
		az.Status = StatusInvalid
	default:
		return chs, nil
	}
	return chs, s.store.UpdateAuthorization(az)
}

func anyChallenge(chs []*Challenge, st Status) bool {
	for _, ch := range chs {
		if ch.Status == st {
			return true
		}
	}
	return false
}

func allChallenges(chs []*Challenge, st Status) bool {
	for _, ch := range chs {
		if ch.Status != st {
			return false
		}
	}
	return len(chs) > 0
}

func (s *Server) renderAuthorization(r *http.Request, az *Authorization, chs []*Challenge) authorizationResponse {
	resp := authorizationResponse{
		Identifier: az.Identifier,
		Status:     az.Status,
		Expires:    az.ExpiresAt.UTC().Format(time.RFC3339),
		Wildcard:   az.Wildcard,
	}
	for _, ch := range chs {
		resp.Challenges = append(resp.Challenges, renderChallenge(r, ch))
	}
	return resp
}

// authorization serves POST-as-GET of an Internal Authorization and
// deactivation by its owner (RFC 8555 §7.5, §7.5.2).
func (s *Server) authorization(w http.ResponseWriter, r *http.Request) {
	acc := accountFrom(r)
	s.mu.Lock()
	defer s.mu.Unlock()

	az, err := s.store.GetAuthorization(chi.URLParam(r, "authzID"))
	if errors.Is(err, ErrNotFound) {
		writeProblem(w, notFound("authorization not found"))
		return
	}
	if err != nil {
		writeProblem(w, serverInternal("error loading authorization"))
		return
	}
	if az.AccountID != acc.ID {
		writeProblem(w, unauthorized("account does not own this authorization"))
		return
	}
	if p := payloadFrom(r); !p.isPostAsGet {
		var req struct {
			Status Status `json:"status"`
		}
		if err := json.Unmarshal(p.value, &req); err != nil || req.Status != StatusDeactivated {
			writeProblem(w, malformed("authorizations can only be deactivated"))
			return
		}
		if az.Status == StatusPending || az.Status == StatusValid {
			az.Status = StatusDeactivated
			if err := s.store.UpdateAuthorization(az); err != nil {
				writeProblem(w, serverInternal("error updating authorization"))
				return
			}
		}
	}
	chs, err := s.refreshAuthorization(az)
	if err != nil {
		writeProblem(w, serverInternal("error refreshing authorization"))
		return
	}
	w.Header().Set("Location", linkURL(r, "authorization", az.ID))
	writeJSON(w, http.StatusOK, s.renderAuthorization(r, az, chs))
}

// challenge serves POST-as-GET of an Internal Challenge, and runs the
// HTTP-01 check when the Requester responds with "{}" (RFC 8555 §7.5.1).
func (s *Server) challenge(w http.ResponseWriter, r *http.Request) {
	acc := accountFrom(r)
	chID := chi.URLParam(r, "challID")

	s.mu.Lock()
	ch, az, perr := s.loadChallenge(acc, chID)
	if perr != nil {
		s.mu.Unlock()
		writeProblem(w, perr)
		return
	}
	if _, err := s.refreshAuthorization(az); err != nil {
		s.mu.Unlock()
		writeProblem(w, serverInternal("error refreshing authorization"))
		return
	}
	attempt := !payloadFrom(r).isPostAsGet && ch.Status == StatusPending && az.Status == StatusPending
	s.mu.Unlock()

	if attempt {
		// The network check runs without holding the lock, and is not cut
		// short if the Requester disconnects.
		result := s.validateHTTP01(s.bgCtx, ch, acc.KeyID)

		s.mu.Lock()
		ch, az, perr = s.loadChallenge(acc, chID)
		if perr == nil && ch.Status == StatusPending {
			now := time.Now()
			if result == nil {
				ch.Status = StatusValid
				ch.ValidatedAt = &now
			} else {
				ch.Status = StatusInvalid
				ch.Error = result
			}
			perr = s.applyChallengeResult(ch, az)
			s.log.Info("internal challenge checked", "account", acc.ID, "authorization", az.ID,
				"host", ch.Host, "status", ch.Status, "error", ch.Error)
		}
		s.mu.Unlock()
		if perr != nil {
			writeProblem(w, perr)
			return
		}
	}

	w.Header().Add("Link", `<`+linkURL(r, "authorization", ch.AuthorizationID)+`>;rel="up"`)
	w.Header().Set("Location", linkURL(r, "challenge", ch.ID))
	writeJSON(w, http.StatusOK, renderChallenge(r, ch))
}

func (s *Server) loadChallenge(acc *Account, id string) (*Challenge, *Authorization, error) {
	ch, err := s.store.GetChallenge(id)
	if errors.Is(err, ErrNotFound) {
		return nil, nil, notFound("challenge not found")
	}
	if err != nil {
		return nil, nil, serverInternal("error loading challenge")
	}
	if ch.AccountID != acc.ID {
		return nil, nil, unauthorized("account does not own this challenge")
	}
	az, err := s.store.GetAuthorization(ch.AuthorizationID)
	if err != nil {
		return nil, nil, serverInternal("error loading authorization")
	}
	return ch, az, nil
}

// applyChallengeResult persists a checked challenge and propagates it to its
// authorization and order. Callers hold s.mu.
func (s *Server) applyChallengeResult(ch *Challenge, az *Authorization) error {
	if err := s.store.UpdateChallenge(ch); err != nil {
		return serverInternal("error updating challenge")
	}
	if _, err := s.refreshAuthorization(az); err != nil {
		return serverInternal("error refreshing authorization")
	}
	o, err := s.store.GetOrder(az.OrderID)
	if err != nil {
		return serverInternal("error loading order")
	}
	if _, err := s.refreshOrder(o); err != nil {
		return serverInternal("error refreshing order")
	}
	return nil
}
