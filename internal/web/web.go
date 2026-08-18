package web

import (
	"embed"
	"path"
	"strings"
)

// assets contains the dependency-free operator interface shipped in the server binary.
//
//go:embed index.html assets/*
var assets embed.FS

type Asset struct {
	Content     []byte
	ContentType string
}

var appRoutes = map[string]bool{
	"/": true, "/sources": true, "/targets": true, "/validations": true,
}

func AppRoute(requestPath string) bool { return appRoutes[requestPath] }

func Lookup(requestPath string) (Asset, bool) {
	if !strings.HasPrefix(requestPath, "/assets/") || path.Clean(requestPath) != requestPath {
		return Asset{}, false
	}
	name := strings.TrimPrefix(requestPath, "/")
	content, err := assets.ReadFile(name)
	if err != nil {
		return Asset{}, false
	}
	contentType := "application/octet-stream"
	switch path.Ext(name) {
	case ".css":
		contentType = "text/css; charset=utf-8"
	case ".js":
		contentType = "text/javascript; charset=utf-8"
	}
	return Asset{Content: content, ContentType: contentType}, true
}

func Index() []byte {
	content, err := assets.ReadFile("index.html")
	if err != nil {
		panic("embedded web index is unavailable")
	}
	return content
}
