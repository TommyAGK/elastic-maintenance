// Package authtest provides authentication doubles for tests only.
// Production server construction must never import this package.
package authtest

import (
	"net/http"

	"elastic-maintenance/internal/auth"
)

type Authenticator struct {
	Actor auth.Actor
	Err   error
}

func (authenticator Authenticator) Authenticate(*http.Request) (auth.Actor, error) {
	if authenticator.Err != nil {
		return auth.Actor{}, authenticator.Err
	}
	actor := authenticator.Actor
	if actor.Method == "" {
		actor.Method = auth.MethodSession
	}
	return actor.Normalized()
}
