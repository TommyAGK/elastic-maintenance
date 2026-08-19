package auth

import (
	"context"
	"errors"
	"net/http"
	"sort"
	"strings"
	"time"
)

var (
	ErrAuthenticationRequired = errors.New("authentication required")
	ErrInvalidAuthentication  = errors.New("invalid authentication")
	ErrSessionExpired         = errors.New("session expired")
	ErrPermissionDenied       = errors.New("permission denied")
)

type Role string

const (
	RoleViewer        Role = "viewer"
	RolePlanner       Role = "planner"
	RoleApplier       Role = "applier"
	RoleAdministrator Role = "administrator"
)

type Permission string

const (
	PermissionSessionRead       Permission = "session.read"
	PermissionSourcesRead       Permission = "sources.read"
	PermissionTargetsRead       Permission = "targets.read"
	PermissionCredentialsRead   Permission = "credentials.status.read"
	PermissionCredentialsWrite  Permission = "credentials.write"
	PermissionValidationsRead   Permission = "validations.read"
	PermissionValidationsCreate Permission = "validations.create"
	PermissionPlansRead         Permission = "plans.read"
	PermissionPlansCreate       Permission = "plans.create"
	PermissionPlansApply        Permission = "plans.apply"
	PermissionJobsRead          Permission = "jobs.read"
	PermissionReportsRead       Permission = "reports.read"
	PermissionAuditRead         Permission = "audit.read"
	PermissionSettingsManage    Permission = "settings.manage"
)

type Method string

const (
	MethodSession    Method = "session"
	MethodOIDC       Method = "oidc"
	MethodBearer     Method = "bearer"
	MethodBreakGlass Method = "break-glass"
)

type Actor struct {
	Subject     string `json:"subject"`
	DisplayName string `json:"displayName,omitempty"`
	Roles       []Role `json:"roles"`
	Method      Method `json:"-"`
}

func (actor Actor) Normalized() (Actor, error) {
	actor.Subject = strings.TrimSpace(actor.Subject)
	actor.DisplayName = strings.TrimSpace(actor.DisplayName)
	if actor.Subject == "" {
		return Actor{}, ErrInvalidAuthentication
	}
	if actor.Method != MethodSession && actor.Method != MethodOIDC && actor.Method != MethodBearer && actor.Method != MethodBreakGlass {
		return Actor{}, ErrInvalidAuthentication
	}

	seen := make(map[Role]struct{}, len(actor.Roles))
	roles := make([]Role, 0, len(actor.Roles))
	for _, role := range actor.Roles {
		if _, ok := rolePermissions[role]; !ok {
			return Actor{}, ErrInvalidAuthentication
		}
		if _, duplicate := seen[role]; duplicate {
			continue
		}
		seen[role] = struct{}{}
		roles = append(roles, role)
	}
	sort.Slice(roles, func(i, j int) bool { return roles[i] < roles[j] })
	actor.Roles = roles
	return actor, nil
}

func (actor Actor) HasPermission(permission Permission) bool {
	for _, role := range actor.Roles {
		if _, ok := rolePermissions[role][permission]; ok {
			return true
		}
	}
	return false
}

type Authenticator interface {
	Authenticate(*http.Request) (Actor, error)
}

type AuthenticatorFunc func(*http.Request) (Actor, error)

func (function AuthenticatorFunc) Authenticate(request *http.Request) (Actor, error) {
	return function(request)
}

type DenyAuthenticator struct{}

func (DenyAuthenticator) Authenticate(*http.Request) (Actor, error) {
	return Actor{}, ErrAuthenticationRequired
}

type Authorizer interface {
	Authorize(Actor, Permission) error
}

type RBACAuthorizer struct{}

func (RBACAuthorizer) Authorize(actor Actor, permission Permission) error {
	normalized, err := actor.Normalized()
	if err != nil {
		return ErrAuthenticationRequired
	}
	if !normalized.HasPermission(permission) {
		return ErrPermissionDenied
	}
	return nil
}

type Session struct {
	Actor     Actor
	ExpiresAt time.Time
}

type SessionManager interface {
	AuthenticateSession(context.Context, string) (Session, error)
	CreateSession(context.Context, Actor) (encodedCookie string, err error)
	DeleteSession(context.Context, string) error
}

type BearerTokenValidator interface {
	ValidateBearerToken(context.Context, string) (Actor, error)
}

func KnownRoles() []Role {
	return []Role{RoleViewer, RolePlanner, RoleApplier, RoleAdministrator}
}

func KnownPermissions() []Permission {
	return []Permission{
		PermissionSessionRead,
		PermissionSourcesRead,
		PermissionTargetsRead,
		PermissionCredentialsRead,
		PermissionCredentialsWrite,
		PermissionValidationsRead,
		PermissionValidationsCreate,
		PermissionPlansRead,
		PermissionPlansCreate,
		PermissionPlansApply,
		PermissionJobsRead,
		PermissionReportsRead,
		PermissionAuditRead,
		PermissionSettingsManage,
	}
}

func permissionSet(values ...Permission) map[Permission]struct{} {
	result := make(map[Permission]struct{}, len(values))
	for _, value := range values {
		result[value] = struct{}{}
	}
	return result
}

var viewerPermissions = []Permission{
	PermissionSessionRead,
	PermissionSourcesRead,
	PermissionTargetsRead,
	PermissionCredentialsRead,
	PermissionValidationsRead,
	PermissionPlansRead,
	PermissionJobsRead,
	PermissionReportsRead,
	PermissionAuditRead,
}

var rolePermissions = map[Role]map[Permission]struct{}{
	RoleViewer: permissionSet(viewerPermissions...),
	RolePlanner: permissionSet(append(append([]Permission{}, viewerPermissions...),
		PermissionValidationsCreate,
		PermissionPlansCreate,
	)...),
	RoleApplier: permissionSet(append(append([]Permission{}, viewerPermissions...),
		PermissionPlansApply,
	)...),
	RoleAdministrator: permissionSet(KnownPermissions()...),
}
