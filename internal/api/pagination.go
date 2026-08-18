package api

import (
	"crypto/sha256"
	"crypto/subtle"
	"encoding/base64"
	"encoding/hex"
	"errors"
	"net/url"
	"strconv"
)

const (
	DefaultPageSize = 50
	MaxPageSize     = 100
)

func ParsePagination(query url.Values, endpoint string) (int, string, error) {
	return ParseNamedPagination(query, endpoint, "pageSize", "pageToken", map[string]bool{"pageSize": true, "pageToken": true})
}

func ParseNamedPagination(query url.Values, endpoint, sizeKey, tokenKey string, allowed map[string]bool) (int, string, error) {
	for key, values := range query {
		if !allowed[key] {
			return 0, "", errors.New("unknown query parameter")
		}
		if len(values) != 1 {
			return 0, "", errors.New("query parameter must appear once")
		}
	}
	pageSize := DefaultPageSize
	if values, exists := query[sizeKey]; exists {
		raw := values[0]
		if raw == "" {
			return 0, "", errors.New("page size must not be empty")
		}
		value, err := strconv.Atoi(raw)
		if err != nil || value < 1 || value > MaxPageSize {
			return 0, "", errors.New("page size must be between 1 and 100")
		}
		pageSize = value
	}
	last := ""
	if values, exists := query[tokenKey]; exists {
		token := values[0]
		if token == "" || len(token) > 512 {
			return 0, "", errors.New("page token is invalid")
		}
		decoded, err := base64.RawURLEncoding.DecodeString(token)
		if err != nil || base64.RawURLEncoding.EncodeToString(decoded) != token {
			return 0, "", errors.New("page token is invalid")
		}
		prefix := endpoint + "\x00"
		if len(decoded) <= len(prefix) || string(decoded[:len(prefix)]) != prefix {
			return 0, "", errors.New("page token is invalid")
		}
		last = string(decoded[len(prefix):])
	}
	return pageSize, last, nil
}

func PageToken(endpoint, last string) string {
	if last == "" {
		return ""
	}
	payload := endpoint + "\x00" + last
	token := base64.RawURLEncoding.EncodeToString([]byte(payload))
	if len(token) <= 512 {
		return token
	}
	payload = endpoint + "\x00" + pageCursorHash(endpoint, last)
	return base64.RawURLEncoding.EncodeToString([]byte(payload))
}

func PageCursorMatches(endpoint, value, cursor string) bool {
	if cursor == value {
		return true
	}
	expected := pageCursorHash(endpoint, value)
	return len(cursor) == len(expected) && subtle.ConstantTimeCompare([]byte(cursor), []byte(expected)) == 1
}

func pageCursorHash(endpoint, value string) string {
	digest := sha256.Sum256([]byte(endpoint + "\x00" + value))
	return "sha256:" + hex.EncodeToString(digest[:])
}
