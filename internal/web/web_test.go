package web

import (
	"bytes"
	"strings"
	"testing"
)

func TestEmbeddedOperatorInterfaceIsSelfContainedAndReadOnly(t *testing.T) {
	index := string(Index())
	for _, required := range []string{"/assets/app.css", "/assets/app.js", "External GitOps owns desired state", "data-view=\"sources\"", "data-view=\"targets\"", "data-view=\"validations\""} {
		if !strings.Contains(index, required) {
			t.Errorf("index does not contain %q", required)
		}
	}
	for _, forbidden := range []string{"https://", "http://", "contenteditable", "resource-edit", "credential"} {
		if strings.Contains(strings.ToLower(index), forbidden) {
			t.Errorf("index contains forbidden %q", forbidden)
		}
	}
	javascript, ok := Lookup("/assets/app.js")
	if !ok || javascript.ContentType != "text/javascript; charset=utf-8" {
		t.Fatalf("JavaScript asset = %#v, %v", javascript, ok)
	}
	for _, required := range [][]byte{[]byte("/api/v1/session"), []byte("/api/v1/sources"), []byte("/api/v1/targets"), []byte("/api/v1/validations"), []byte("method:\"POST\""), []byte("Idempotency-Key"), []byte("/auth/logout"), []byte("authenticationMethod")} {
		if !bytes.Contains(javascript.Content, required) {
			t.Errorf("JavaScript does not contain %q", required)
		}
	}
	for _, forbidden := range [][]byte{[]byte("localStorage"), []byte("sessionStorage"), []byte("innerHTML"), []byte("eval(")} {
		if bytes.Contains(javascript.Content, forbidden) {
			t.Errorf("JavaScript contains forbidden %q", forbidden)
		}
	}
}

func TestLookupRejectsUnknownAndNonCanonicalAssets(t *testing.T) {
	for _, requestPath := range []string{"/assets/missing.js", "/assets/../index.html", "//assets/app.js", "/index.html"} {
		if _, ok := Lookup(requestPath); ok {
			t.Errorf("Lookup(%q) succeeded", requestPath)
		}
	}
	if asset, ok := Lookup("/assets/app.css"); !ok || asset.ContentType != "text/css; charset=utf-8" || len(asset.Content) == 0 {
		t.Fatalf("CSS asset = %#v, %v", asset, ok)
	}
}

func TestAppRoutesAreExplicit(t *testing.T) {
	for _, route := range []string{"/", "/sources", "/targets", "/validations"} {
		if !AppRoute(route) {
			t.Errorf("AppRoute(%q) = false", route)
		}
	}
	for _, route := range []string{"/missing", "/sources/anything", "/api/v1"} {
		if AppRoute(route) {
			t.Errorf("AppRoute(%q) = true", route)
		}
	}
}
