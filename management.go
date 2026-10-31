package api

import (
	"context"
	"crypto/sha256"
	"encoding/json"
	"errors"
	"math"
	"slices"
	"time"
)

// CredentialDetails reads consistent current management state from the primary.
func (s *Service) CredentialDetails(ctx context.Context, id string) (CredentialDetails, error) {
	ctx, done, err := s.begin(ctx)
	if err != nil {
		return CredentialDetails{}, err
	}
	defer done()
	store, ok := s.store.(ManagementStore)
	if !ok {
		return CredentialDetails{}, ErrUnsupported
	}
	return store.CredentialDetails(ctx, id)
}

// SecretVersions lists newest generations first; zero before starts at the newest.
func (s *Service) SecretVersions(ctx context.Context, id string, before int64, limit int) ([]SecretVersionInfo, error) {
	ctx, done, err := s.begin(ctx)
	if err != nil {
		return nil, err
	}
	defer done()
	if before < 0 || limit < 1 || limit > 1000 {
		return nil, ErrInvalid
	}
	store, ok := s.store.(ManagementStore)
	if !ok {
		return nil, ErrUnsupported
	}
	return store.SecretVersions(ctx, id, before, limit)
}

// RetireVersion shortens only a historical version's deadline, never the current one.
func (s *Service) RetireVersion(ctx context.Context, credentialID, versionID string) error {
	ctx, done, err := s.begin(ctx)
	if err != nil {
		return err
	}
	defer done()
	actor, err := s.actor(ctx)
	if err != nil {
		return err
	}
	if s.settings.audit {
		store, ok := s.store.(AuditedRetirementStore)
		if !ok {
			return ErrUnsupported
		}
		err = store.RetireVersionAudited(ctx, actor, credentialID, versionID)
	} else {
		store, ok := s.store.(ManagementStore)
		if !ok {
			return ErrUnsupported
		}
		err = store.RetireVersion(ctx, credentialID, versionID)
	}
	if err != nil {
		return s.writeError(err, "", credentialID)
	}
	s.invalidateFor("", credentialID)
	return nil
}

// Operation returns a committed receipt. ErrNotFound does not prove rollback.
func (s *Service) Operation(ctx context.Context, id string) (OperationReceipt, error) {
	ctx, done, err := s.begin(ctx)
	if err != nil {
		return OperationReceipt{}, err
	}
	defer done()
	if !validOperationID(id) {
		return OperationReceipt{}, ErrInvalid
	}
	store, ok := s.store.(OperationStore)
	if !ok {
		return OperationReceipt{}, ErrUnsupported
	}
	return store.Operation(ctx, id)
}

func validOperationID(id string) bool {
	if len(id) == 0 || len(id) > 128 {
		return false
	}
	for _, c := range id {
		if c < '!' || c > '~' {
			return false
		}
	}
	return true
}

func operationSpec(id, kind string, request any, actor Actor) (OperationSpec, error) {
	if !validOperationID(id) {
		return OperationSpec{}, ErrInvalid
	}
	body, err := json.Marshal(struct {
		Kind    string `json:"kind"`
		Request any    `json:"request"`
		Actor   Actor  `json:"actor"`
	}{kind, request, actor})
	if err != nil {
		return OperationSpec{}, err
	}
	return OperationSpec{ID: id, Fingerprint: sha256.Sum256(body)}, nil
}

func replay(ctx context.Context, store OperationStore, spec OperationSpec) (OperationResult, bool, error) {
	receipt, err := store.Operation(ctx, spec.ID)
	if errors.Is(err, ErrNotFound) {
		return OperationResult{}, false, nil
	}
	if err != nil {
		return OperationResult{}, false, err
	}
	if receipt.Fingerprint != spec.Fingerprint {
		return OperationResult{}, false, ErrConflict
	}
	return OperationResult{Receipt: receipt}, true, nil
}

// IssueOnce creates at most one committed credential per schema and operation ID.
// A replay returns a receipt without the unrecoverable plaintext token.
func (s *Service) IssueOnce(ctx context.Context, id string, req IssueRequest) (OperationResult, error) {
	ctx, done, err := s.begin(ctx)
	if err != nil {
		return OperationResult{}, err
	}
	defer done()
	actor, err := s.actor(ctx)
	if err != nil {
		return OperationResult{}, err
	}
	store, ok := s.store.(OperationStore)
	if !ok {
		return OperationResult{}, ErrUnsupported
	}
	audited, auditOK := s.store.(AuditedOperationStore)
	if s.settings.audit && !auditOK {
		return OperationResult{}, ErrUnsupported
	}
	req.Scopes = slices.Clone(req.Scopes)
	slices.Sort(req.Scopes)
	req.Scopes = slices.Compact(req.Scopes)
	if len(req.Scopes) == 0 {
		req.Scopes = nil
	}
	spec, err := operationSpec(id, "issue", map[string]any{
		"client_id": req.ClientID, "name": req.Name, "scopes": req.Scopes, "ttl": req.TTL,
	}, actor)
	if err != nil {
		return OperationResult{}, err
	}
	if result, found, replayErr := replay(ctx, store, spec); found || replayErr != nil {
		return result, replayErr
	}
	if !validName(req.Name) {
		return OperationResult{}, ErrInvalid
	}
	scopes, err := s.scopes(req.Scopes)
	if err != nil {
		return OperationResult{}, err
	}
	cred := Credential{
		ID: newID(), ClientID: req.ClientID, Name: req.Name, Scopes: scopes, Generation: 1, CreatedAt: s.settings.now().UTC(),
	}
	version, token, err := s.secret(cred.ID, 1, req.TTL)
	if err != nil {
		return OperationResult{}, err
	}
	var receipt OperationReceipt
	var applied bool
	if s.settings.audit {
		receipt, applied, err = audited.IssueOnceAudited(ctx, actor, spec, cred, version, mustTTL(s, req.TTL))
	} else {
		receipt, applied, err = store.IssueOnce(ctx, spec, cred, version, mustTTL(s, req.TTL))
	}
	return s.operationResult(receipt, applied, token, err, req.ClientID, cred.ID)
}

// RotateOnce makes a generation-checked rotation safe to retry with the same ID.
func (s *Service) RotateOnce(ctx context.Context, id string, req RotateRequest) (OperationResult, error) {
	ctx, done, err := s.begin(ctx)
	if err != nil {
		return OperationResult{}, err
	}
	defer done()
	actor, err := s.actor(ctx)
	if err != nil {
		return OperationResult{}, err
	}
	store, ok := s.store.(OperationStore)
	if !ok {
		return OperationResult{}, ErrUnsupported
	}
	audited, auditOK := s.store.(AuditedOperationStore)
	if s.settings.audit && !auditOK {
		return OperationResult{}, ErrUnsupported
	}
	spec, err := operationSpec(id, "rotate", map[string]any{
		"credential_id": req.CredentialID, "generation": req.ExpectedGeneration, "ttl": req.TTL, "grace": req.GracePeriod,
	}, actor)
	if err != nil {
		return OperationResult{}, err
	}
	if result, found, replayErr := replay(ctx, store, spec); found || replayErr != nil {
		return result, replayErr
	}
	if req.ExpectedGeneration < 1 || req.ExpectedGeneration == math.MaxInt64 || req.GracePeriod < 0 {
		return OperationResult{}, ErrInvalid
	}
	version, token, err := s.secret(req.CredentialID, req.ExpectedGeneration+1, req.TTL)
	if err != nil {
		return OperationResult{}, err
	}
	var receipt OperationReceipt
	var applied bool
	if s.settings.audit {
		receipt, applied, err = audited.RotateOnceAudited(
			ctx, actor, spec, req.CredentialID, req.ExpectedGeneration, version, mustTTL(s, req.TTL), req.GracePeriod,
		)
	} else {
		receipt, applied, err = store.RotateOnce(
			ctx, spec, req.CredentialID, req.ExpectedGeneration, version, mustTTL(s, req.TTL), req.GracePeriod,
		)
	}
	return s.operationResult(receipt, applied, token, err, "", req.CredentialID)
}

func (s *Service) operationResult(
	receipt OperationReceipt, applied bool, token string, err error, clientID, credentialID string,
) (OperationResult, error) {
	if err != nil {
		return OperationResult{}, s.writeError(err, clientID, credentialID)
	}
	result := OperationResult{Receipt: receipt}
	if applied {
		s.invalidateFor(clientID, credentialID)
		result.Issued = &Issued{Credential: receipt.Credential, Token: token, ExpiresAt: receipt.Version.ExpiresAt}
	}
	return result, nil
}

// AuditEvents lists newest events first; before=0 starts at the newest event.
func (s *Service) AuditEvents(ctx context.Context, before int64, limit int) ([]AuditEvent, error) {
	ctx, done, err := s.begin(ctx)
	if err != nil {
		return nil, err
	}
	defer done()
	if before < 0 || limit < 1 || limit > 1000 {
		return nil, ErrInvalid
	}
	store, ok := s.store.(AuditReader)
	if !ok {
		return nil, ErrUnsupported
	}
	return store.AuditEvents(ctx, before, limit)
}

// PruneAuditEvents removes only the host-selected historical window in small batches.
func (s *Service) PruneAuditEvents(ctx context.Context, before time.Time, limit int) (int64, error) {
	ctx, done, err := s.begin(ctx)
	if err != nil {
		return 0, err
	}
	defer done()
	if before.IsZero() || before.After(s.settings.now()) || limit < 1 || limit > 1000 {
		return 0, ErrInvalid
	}
	if _, err := s.actor(ctx); err != nil {
		return 0, err
	}
	store, ok := s.store.(AuditReader)
	if !ok {
		return 0, ErrUnsupported
	}
	return store.PruneAuditEvents(ctx, before, limit)
}
