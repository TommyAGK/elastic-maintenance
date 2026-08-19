package auth

import (
	"errors"
	"net/http"
)

// CompositeAuthenticator dispatches the single protected browser-session cookie
// across explicit session issuers. It does not initiate or fall back between
// login mechanisms.
type CompositeAuthenticator struct{ authenticators []Authenticator }

func NewCompositeAuthenticator(authenticators ...Authenticator) Authenticator {
	filtered := make([]Authenticator, 0, len(authenticators))
	for _, item := range authenticators {
		if item != nil {
			filtered = append(filtered, item)
		}
	}
	if len(filtered) == 1 {
		return filtered[0]
	}
	return &CompositeAuthenticator{authenticators: filtered}
}

func (composite *CompositeAuthenticator) Authenticate(request *http.Request) (Actor, error) {
	if composite == nil || len(composite.authenticators) == 0 {
		return Actor{}, ErrAuthenticationRequired
	}
	result := ErrAuthenticationRequired
	for _, item := range composite.authenticators {
		actor, err := item.Authenticate(request)
		if err == nil {
			return actor, nil
		}
		if errors.Is(err, ErrAuthenticationConflict) {
			return Actor{}, err
		}
		if errors.Is(err, ErrSessionExpired) {
			result = err
		} else if result != ErrSessionExpired && !errors.Is(err, ErrAuthenticationRequired) {
			result = ErrInvalidAuthentication
		}
	}
	return Actor{}, result
}
