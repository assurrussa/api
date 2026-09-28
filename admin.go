package api

import (
	"context"
	"errors"
	"fmt"
	"math"
	"time"
)

// A transport or commit error can mean that the write reached the authority.
// Invalidate conservatively; domain errors describe a definite rejection.
func (s *Service) writeError(err error, clientID, credentialID string) error {
	if err != nil && !errors.Is(err, ErrInvalid) && !errors.Is(err, ErrForbidden) &&
		!errors.Is(err, ErrNotFound) && !errors.Is(err, ErrConflict) {
		s.invalidateFor(clientID, credentialID)
	}
	return err
}

func (s *Service) CreateClient(ctx context.Context, name string, scopes []string) (Client, error) {
	ctx, done, err := s.begin(ctx)
	if err != nil {
		return Client{}, err
	}
	defer done()
	if !validName(name) {
		return Client{}, fmt.Errorf("%w: client name", ErrInvalid)
	}
	grants, err := s.scopes(scopes)
	if err != nil {
		return Client{}, err
	}
	client := Client{ID: newID(), Name: name, Scopes: grants, CreatedAt: s.settings.now().UTC()}
	if err := s.store.CreateClient(ctx, client); err != nil {
		return Client{}, s.writeError(err, client.ID, "")
	}
	s.invalidateFor(client.ID, "")
	return client, nil
}

func (s *Service) Client(ctx context.Context, id string) (Client, error) {
	ctx, done, err := s.begin(ctx)
	if err != nil {
		return Client{}, err
	}
	defer done()
	return s.store.Client(ctx, id)
}

func (s *Service) Clients(ctx context.Context, after string, limit int) ([]Client, error) {
	ctx, done, err := s.begin(ctx)
	if err != nil {
		return nil, err
	}
	defer done()
	if limit < 1 || limit > 1000 {
		return nil, ErrInvalid
	}
	return s.store.Clients(ctx, after, limit)
}

func (s *Service) SetClientScopes(ctx context.Context, id string, scopes []string) error {
	ctx, done, err := s.begin(ctx)
	if err != nil {
		return err
	}
	defer done()
	grants, err := s.scopes(scopes)
	if err != nil {
		return err
	}
	if err := s.store.SetClientScopes(ctx, id, grants); err != nil {
		return s.writeError(err, id, "")
	}
	s.invalidateFor(id, "")
	return nil
}

func (s *Service) SetClientBanned(ctx context.Context, id string, banned bool) error {
	ctx, done, err := s.begin(ctx)
	if err != nil {
		return err
	}
	defer done()
	if err := s.store.SetClientBanned(ctx, id, banned); err != nil {
		return s.writeError(err, id, "")
	}
	s.invalidateFor(id, "")
	return nil
}

func (s *Service) Issue(ctx context.Context, req IssueRequest) (Issued, error) {
	ctx, done, err := s.begin(ctx)
	if err != nil {
		return Issued{}, err
	}
	defer done()
	if !validName(req.Name) {
		return Issued{}, ErrInvalid
	}
	scopes, err := s.scopes(req.Scopes)
	if err != nil {
		return Issued{}, err
	}
	credential := Credential{
		ID:         newID(),
		ClientID:   req.ClientID,
		Name:       req.Name,
		Scopes:     scopes,
		Generation: 1,
		CreatedAt:  s.settings.now().UTC(),
	}
	version, token, err := s.secret(credential.ID, 1, req.TTL)
	if err != nil {
		return Issued{}, err
	}
	if timed, ok := s.store.(TimedStore); ok {
		credential, version, err = timed.IssueWithLifetime(ctx, credential, version, mustTTL(s, req.TTL))
	} else {
		err = s.store.Issue(ctx, credential, version)
	}
	if err != nil {
		return Issued{}, s.writeError(err, req.ClientID, credential.ID)
	}
	s.invalidateFor(req.ClientID, credential.ID)
	return Issued{Credential: credential, Token: token, ExpiresAt: version.ExpiresAt}, nil
}

func (s *Service) Rotate(ctx context.Context, req RotateRequest) (Issued, error) {
	ctx, done, err := s.begin(ctx)
	if err != nil {
		return Issued{}, err
	}
	defer done()
	if req.ExpectedGeneration < 1 || req.ExpectedGeneration == math.MaxInt64 || req.GracePeriod < 0 {
		return Issued{}, ErrInvalid
	}
	version, token, err := s.secret(req.CredentialID, req.ExpectedGeneration+1, req.TTL)
	if err != nil {
		return Issued{}, err
	}
	var credential Credential
	if timed, ok := s.store.(TimedStore); ok {
		credential, version, err = timed.RotateWithLifetime(
			ctx, req.CredentialID, req.ExpectedGeneration, version, mustTTL(s, req.TTL), req.GracePeriod,
		)
	} else {
		credential, err = s.store.Rotate(ctx, req.CredentialID, req.ExpectedGeneration, version, req.GracePeriod, version.CreatedAt)
	}
	if err != nil {
		return Issued{}, s.writeError(err, "", req.CredentialID)
	}
	s.invalidateFor("", req.CredentialID)
	return Issued{Credential: credential, Token: token, ExpiresAt: version.ExpiresAt}, nil
}

// secret validated this TTL before the TimedStore path is reached.
func mustTTL(s *Service, ttl time.Duration) time.Duration {
	if ttl == 0 {
		return s.cfg.DefaultTTL
	}
	return ttl
}

func (s *Service) Credential(ctx context.Context, id string) (Credential, error) {
	ctx, done, err := s.begin(ctx)
	if err != nil {
		return Credential{}, err
	}
	defer done()
	return s.store.Credential(ctx, id)
}

func (s *Service) Credentials(ctx context.Context, clientID, after string, limit int) ([]Credential, error) {
	ctx, done, err := s.begin(ctx)
	if err != nil {
		return nil, err
	}
	defer done()
	if limit < 1 || limit > 1000 {
		return nil, ErrInvalid
	}
	return s.store.Credentials(ctx, clientID, after, limit)
}

func (s *Service) Revoke(ctx context.Context, id string) error {
	ctx, done, err := s.begin(ctx)
	if err != nil {
		return err
	}
	defer done()
	if err := s.store.Revoke(ctx, id, s.settings.now().UTC()); err != nil {
		return s.writeError(err, "", id)
	}
	s.invalidateFor("", id)
	return nil
}

func (s *Service) RevokeAll(ctx context.Context, clientID string) error {
	ctx, done, err := s.begin(ctx)
	if err != nil {
		return err
	}
	defer done()
	if err := s.store.RevokeAll(ctx, clientID, s.settings.now().UTC()); err != nil {
		return s.writeError(err, clientID, "")
	}
	s.invalidateFor(clientID, "")
	return nil
}
