package api

import _ "embed"

//go:embed openapi.json
var openAPIDocument []byte

func OpenAPIDocument() []byte {
	return append([]byte(nil), openAPIDocument...)
}
