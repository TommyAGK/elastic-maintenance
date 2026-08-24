package auth

import (
	"context"
	"crypto/aes"
	"crypto/cipher"
	"crypto/hmac"
	"crypto/rand"
	"crypto/sha256"
	"crypto/subtle"
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"net/http"
	"regexp"
	"strconv"
	"strings"
	"time"

	"github.com/TommyAGK/elastic-maintenance/internal/config"
	"github.com/TommyAGK/elastic-maintenance/internal/secretmount"
)

const (
	SessionCookieName     = "__Host-elastic-maintainer-session"
	TransactionCookieName = "__Host-elastic-maintainer-oidc"
	keyRingHeader         = "elastic-maintainer-session-keyring/v1"
	maxCookieBytes        = 4096
	maxPreviousKeys       = 2
)

var keyIDPattern = regexp.MustCompile(`^[A-Za-z0-9_-]{1,32}$`)

type keyRingSource struct {
	reader secretmount.Reader
	ref    config.SecretKeyRef
}
type cookieKey struct {
	id    string
	value []byte
}
type keyRing struct {
	current cookieKey
	all     map[string]cookieKey
}

func newKeyRingSource(reader secretmount.Reader, ref config.SecretKeyRef) (*keyRingSource, error) {
	if reader == nil {
		return nil, errors.New("session key reader is required")
	}
	source := &keyRingSource{reader: reader, ref: ref}
	if _, err := source.load(context.Background()); err != nil {
		return nil, err
	}
	return source, nil
}
func (source *keyRingSource) load(ctx context.Context) (keyRing, error) {
	contents, err := source.reader.Read(ctx, source.ref)
	if err != nil {
		return keyRing{}, errors.New("session key ring is unavailable")
	}
	lines := strings.Split(strings.TrimSuffix(string(contents), "\n"), "\n")
	if len(lines) < 2 || len(lines) > 2+maxPreviousKeys || lines[0] != keyRingHeader {
		return keyRing{}, errors.New("session key ring is invalid")
	}
	result := keyRing{all: make(map[string]cookieKey, len(lines)-1)}
	for index, line := range lines[1:] {
		parts := strings.Split(line, " ")
		expected := "previous"
		if index == 0 {
			expected = "current"
		}
		if len(parts) != 3 || parts[0] != expected || !keyIDPattern.MatchString(parts[1]) {
			return keyRing{}, errors.New("session key ring is invalid")
		}
		decoded, decodeErr := base64.RawURLEncoding.Strict().DecodeString(parts[2])
		if decodeErr != nil || len(decoded) != 32 {
			return keyRing{}, errors.New("session key ring is invalid")
		}
		if _, duplicate := result.all[parts[1]]; duplicate {
			return keyRing{}, errors.New("session key ring is invalid")
		}
		key := cookieKey{id: parts[1], value: decoded}
		result.all[key.id] = key
		if index == 0 {
			result.current = key
		}
	}
	return result, nil
}

type cookieCodec struct {
	keys *keyRingSource
	now  func() time.Time
}

func newCookieCodec(keys *keyRingSource, now func() time.Time) *cookieCodec {
	if now == nil {
		now = time.Now
	}
	return &cookieCodec{keys: keys, now: now}
}
func (codec *cookieCodec) encode(ctx context.Context, purpose string, value any) (string, error) {
	ring, err := codec.keys.load(ctx)
	if err != nil {
		return "", err
	}
	plaintext, err := json.Marshal(value)
	if err != nil {
		return "", errors.New("encode protected cookie")
	}
	block, err := aes.NewCipher(deriveCookieKey(ring.current.value, purpose))
	if err != nil {
		return "", errors.New("protect cookie")
	}
	gcm, err := cipher.NewGCM(block)
	if err != nil {
		return "", errors.New("protect cookie")
	}
	nonce := make([]byte, gcm.NonceSize())
	if _, err := rand.Read(nonce); err != nil {
		return "", errors.New("protect cookie")
	}
	aad := cookieAAD(purpose, ring.current.id)
	sealed := gcm.Seal(nonce, nonce, plaintext, aad)
	encoded := "v1." + ring.current.id + "." + base64.RawURLEncoding.EncodeToString(sealed)
	if len(encoded) > maxCookieBytes {
		return "", errors.New("protected cookie exceeds limit")
	}
	return encoded, nil
}
func (codec *cookieCodec) decode(ctx context.Context, purpose, encoded string, destination any) error {
	parts, err := parseProtectedCookie(encoded)
	if err != nil {
		return err
	}
	ring, err := codec.keys.load(ctx)
	if err != nil {
		return err
	}
	key, exists := ring.all[parts.keyID]
	if !exists {
		return errors.New("protected cookie is invalid")
	}
	return decodeProtectedCookie(parts, key, purpose, destination)
}

// decodeCurrent is deliberately stricter than decode: sessions which were
// encrypted with a previous key remain useful to OIDC's rotation overlap, but
// are not accepted for break-glass access. This lets key rotation immediately
// terminate emergency sessions without changing OIDC behavior.
func (codec *cookieCodec) decodeCurrent(ctx context.Context, purpose, encoded string, destination any) error {
	parts, err := parseProtectedCookie(encoded)
	if err != nil {
		return err
	}
	ring, err := codec.keys.load(ctx)
	if err != nil {
		return err
	}
	if parts.keyID != ring.current.id {
		return errors.New("protected cookie is invalid")
	}
	return decodeProtectedCookie(parts, ring.current, purpose, destination)
}

type protectedCookie struct {
	keyID  string
	sealed []byte
}

func parseProtectedCookie(encoded string) (protectedCookie, error) {
	if len(encoded) == 0 || len(encoded) > maxCookieBytes {
		return protectedCookie{}, errors.New("protected cookie is invalid")
	}
	parts := strings.Split(encoded, ".")
	if len(parts) != 3 || parts[0] != "v1" || !keyIDPattern.MatchString(parts[1]) {
		return protectedCookie{}, errors.New("protected cookie is invalid")
	}
	sealed, err := base64.RawURLEncoding.Strict().DecodeString(parts[2])
	if err != nil {
		return protectedCookie{}, errors.New("protected cookie is invalid")
	}
	return protectedCookie{keyID: parts[1], sealed: sealed}, nil
}

func decodeProtectedCookie(parts protectedCookie, key cookieKey, purpose string, destination any) error {
	block, _ := aes.NewCipher(deriveCookieKey(key.value, purpose))
	gcm, _ := cipher.NewGCM(block)
	if len(parts.sealed) < gcm.NonceSize() {
		return errors.New("protected cookie is invalid")
	}
	plaintext, err := gcm.Open(nil, parts.sealed[:gcm.NonceSize()], parts.sealed[gcm.NonceSize():], cookieAAD(purpose, key.id))
	if err != nil {
		return errors.New("protected cookie is invalid")
	}
	decoder := json.NewDecoder(strings.NewReader(string(plaintext)))
	decoder.DisallowUnknownFields()
	if err := decoder.Decode(destination); err != nil {
		return errors.New("protected cookie is invalid")
	}
	return nil
}
func deriveCookieKey(secret []byte, purpose string) []byte {
	mac := hmac.New(sha256.New, secret)
	_, _ = mac.Write([]byte("elastic-maintainer/cookie-key/v1\x00" + purpose))
	return mac.Sum(nil)
}
func cookieAAD(purpose, id string) []byte {
	return []byte("elastic-maintainer/cookie/v1\x00" + purpose + "\x00" + id)
}

type sessionPayload struct {
	Version   string `json:"v"`
	Actor     Actor  `json:"actor"`
	Method    Method `json:"method"`
	Revision  string `json:"rev,omitempty"`
	CSRFToken string `json:"csrf,omitempty"`
	IssuedAt  int64  `json:"iat"`
	ExpiresAt int64  `json:"exp"`
}
type transactionPayload struct {
	Version   string `json:"v"`
	State     string `json:"state"`
	Nonce     string `json:"nonce"`
	Verifier  string `json:"verifier"`
	IssuedAt  int64  `json:"iat"`
	ExpiresAt int64  `json:"exp"`
}

func hasNamedCookie(request *http.Request, name string) bool {
	for _, item := range request.Cookies() {
		if item.Name == name {
			return true
		}
	}
	return false
}
func readUniqueCookie(request *http.Request, name string) (string, error) {
	values := make([]string, 0, 1)
	for _, item := range request.Cookies() {
		if item.Name == name {
			values = append(values, item.Value)
		}
	}
	if len(values) == 0 {
		return "", ErrAuthenticationRequired
	}
	if len(values) > 1 {
		return "", ErrAuthenticationConflict
	}
	return values[0], nil
}
func setProtectedCookie(w http.ResponseWriter, name, value string, expires time.Time) {
	http.SetCookie(w, &http.Cookie{Name: name, Value: value, Path: "/", Expires: expires, MaxAge: int(time.Until(expires).Seconds()), Secure: true, HttpOnly: true, SameSite: http.SameSiteLaxMode})
}
func clearProtectedCookie(w http.ResponseWriter, name string) {
	http.SetCookie(w, &http.Cookie{Name: name, Value: "", Path: "/", Expires: time.Unix(1, 0), MaxAge: -1, Secure: true, HttpOnly: true, SameSite: http.SameSiteLaxMode})
}

func randomURLValue(bytes int) (string, error) {
	value := make([]byte, bytes)
	if _, err := rand.Read(value); err != nil {
		return "", errors.New("generate authentication value")
	}
	return base64.RawURLEncoding.EncodeToString(value), nil
}
func constantTimeEqual(left, right string) bool {
	return len(left) == len(right) && subtle.ConstantTimeCompare([]byte(left), []byte(right)) == 1
}
func validAbsoluteTimes(now time.Time, issued, expires int64, maximum time.Duration) bool {
	i, e := time.Unix(issued, 0), time.Unix(expires, 0)
	return !i.After(now.Add(time.Minute)) && e.After(now) && e.After(i) && e.Sub(i) <= maximum
}
func parseSingleQuery(request *http.Request, key string) (string, error) {
	values, exists := request.URL.Query()[key]
	if !exists || len(values) != 1 || values[0] == "" {
		return "", fmt.Errorf("%s is required", key)
	}
	return values[0], nil
}
func rejectUnexpectedQuery(request *http.Request, allowed ...string) error {
	set := map[string]bool{}
	for _, item := range allowed {
		set[item] = true
	}
	for key, values := range request.URL.Query() {
		if !set[key] || len(values) != 1 {
			return errors.New("callback query is invalid")
		}
	}
	return nil
}
func formatUnix(value int64) string { return strconv.FormatInt(value, 10) }
