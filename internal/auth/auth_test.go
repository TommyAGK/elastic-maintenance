package auth

import (
	"context"
	"errors"
	"net/http/httptest"
	"reflect"
	"testing"
)

func TestRolePermissions(t *testing.T) {
	viewer := actorWithRoles(RoleViewer)
	planner := actorWithRoles(RolePlanner)
	applier := actorWithRoles(RoleApplier)
	administrator := actorWithRoles(RoleAdministrator)

	for _, permission := range viewerPermissions {
		if !viewer.HasPermission(permission) || !planner.HasPermission(permission) || !applier.HasPermission(permission) || !administrator.HasPermission(permission) {
			t.Errorf("viewer permission %q was not inherited by every role", permission)
		}
	}
	if viewer.HasPermission(PermissionPlansCreate) || viewer.HasPermission(PermissionPlansApply) || viewer.HasPermission(PermissionCredentialsWrite) {
		t.Fatal("viewer received a mutation permission")
	}
	if !planner.HasPermission(PermissionValidationsCreate) || !planner.HasPermission(PermissionPlansCreate) || planner.HasPermission(PermissionPlansApply) {
		t.Fatal("planner permissions are incorrect")
	}
	if !applier.HasPermission(PermissionPlansApply) || applier.HasPermission(PermissionPlansCreate) {
		t.Fatal("applier permissions are incorrect")
	}
	for _, permission := range KnownPermissions() {
		if !administrator.HasPermission(permission) {
			t.Errorf("administrator lacks %q", permission)
		}
	}
}

func TestActorNormalized(t *testing.T) {
	actor := Actor{
		Subject:     " user-1 ",
		DisplayName: " Operator ",
		Roles:       []Role{RoleViewer, RoleAdministrator, RoleViewer},
		Method:      MethodBearer,
	}
	got, err := actor.Normalized()
	if err != nil {
		t.Fatal(err)
	}
	wantRoles := []Role{RoleAdministrator, RoleViewer}
	if got.Subject != "user-1" || got.DisplayName != "Operator" || !reflect.DeepEqual(got.Roles, wantRoles) {
		t.Fatalf("Normalized() = %#v", got)
	}
}

func TestActorNormalizedRejectsInvalidIdentity(t *testing.T) {
	for name, actor := range map[string]Actor{
		"empty subject":  {Roles: []Role{RoleViewer}, Method: MethodSession},
		"unknown role":   {Subject: "user", Roles: []Role{"owner"}, Method: MethodSession},
		"unknown method": {Subject: "user", Roles: []Role{RoleViewer}, Method: "password"},
	} {
		t.Run(name, func(t *testing.T) {
			if _, err := actor.Normalized(); !errors.Is(err, ErrInvalidAuthentication) {
				t.Fatalf("Normalized() error = %v", err)
			}
		})
	}
}

func TestMultiRolePermissionsAreUnioned(t *testing.T) {
	actor := actorWithRoles(RolePlanner, RoleApplier)
	if !actor.HasPermission(PermissionPlansCreate) || !actor.HasPermission(PermissionPlansApply) {
		t.Fatalf("multi-role actor permissions were not unioned: %#v", actor)
	}
}

func TestRBACAuthorizer(t *testing.T) {
	authorizer := RBACAuthorizer{}
	if err := authorizer.Authorize(actorWithRoles(RolePlanner), PermissionPlansCreate); err != nil {
		t.Fatalf("Authorize() error = %v", err)
	}
	if err := authorizer.Authorize(actorWithRoles(RoleViewer), PermissionPlansCreate); !errors.Is(err, ErrPermissionDenied) {
		t.Fatalf("Authorize() error = %v", err)
	}
	if err := authorizer.Authorize(Actor{}, PermissionSourcesRead); !errors.Is(err, ErrAuthenticationRequired) {
		t.Fatalf("Authorize() invalid actor error = %v", err)
	}
}

func TestDenyAuthenticator(t *testing.T) {
	_, err := (DenyAuthenticator{}).Authenticate(httptest.NewRequest("GET", "/api/v1/session", nil))
	if !errors.Is(err, ErrAuthenticationRequired) {
		t.Fatalf("Authenticate() error = %v", err)
	}
}

func TestActorContext(t *testing.T) {
	want := actorWithRoles(RoleViewer)
	ctx := WithActor(context.Background(), want)
	got, ok := ActorFromContext(ctx)
	if !ok || !reflect.DeepEqual(got, want) {
		t.Fatalf("ActorFromContext() = %#v, %v", got, ok)
	}
	if _, ok := ActorFromContext(context.Background()); ok {
		t.Fatal("ActorFromContext() unexpectedly found an actor")
	}
}

func TestKnownRoleAndPermissionListsAreCopies(t *testing.T) {
	roles := KnownRoles()
	roles[0] = "changed"
	if KnownRoles()[0] != RoleViewer {
		t.Fatal("KnownRoles returned shared mutable storage")
	}
	permissions := KnownPermissions()
	permissions[0] = "changed"
	if KnownPermissions()[0] != PermissionSessionRead {
		t.Fatal("KnownPermissions returned shared mutable storage")
	}
}

func actorWithRoles(roles ...Role) Actor {
	return Actor{Subject: "user-1", DisplayName: "Operator", Roles: roles, Method: MethodSession}
}
