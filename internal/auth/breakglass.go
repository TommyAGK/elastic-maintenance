package auth

import (
	"context"
	"crypto/sha256"
	"crypto/subtle"
	"encoding/base64"
	"encoding/binary"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"mime"
	"net"
	"net/http"
	"net/url"
	"strings"
	"sync"
	"time"

	"github.com/TommyAGK/elastic-maintenance/internal/config"
	"github.com/TommyAGK/elastic-maintenance/internal/secretmount"
	"golang.org/x/crypto/argon2"
)

const (
	BreakGlassSessionLifetime = 15 * time.Minute

	// These limits are deliberately independent of the mounted-reader limit. A
	// break-glass document is a tiny, fixed-format credential, not an arbitrary
	// Secret value.
	BreakGlassCredentialDocumentMaxBytes = 16 << 10
	BreakGlassVerifierMaxBytes           = 512
	BreakGlassGenerationMaxBytes         = 64
	BreakGlassPasswordMaxBytes           = 1024
	BreakGlassLoginBodyMaxBytes          = 8 << 10

	breakGlassCredentialHeader = "elastic-maintainer-break-glass/v1"
	breakGlassArgonMemory      = 65536
	breakGlassArgonTime        = 3
	breakGlassArgonThreads     = 1
	breakGlassArgonSaltBytes   = 16
	breakGlassArgonHashBytes   = 32
	breakGlassRevisionHeader   = "elastic-maintainer-break-glass-revision/v1"
)

var (
	ErrBreakGlassDisabled             = errors.New("break-glass authentication is disabled")
	ErrBreakGlassAuthenticationFailed = errors.New("break-glass authentication failed")
	ErrBreakGlassThrottled            = errors.New("break-glass authentication throttled")
	ErrBreakGlassMethodNotAllowed     = errors.New("break-glass login method is not allowed")
	ErrBreakGlassInvalidRequest       = errors.New("break-glass login request is invalid")

	// Short aliases make the safe outcomes convenient for HTTP adapters while
	// retaining the more specific names for callers that have several auth
	// mechanisms.
	ErrBreakGlassFailed        = ErrBreakGlassAuthenticationFailed
	ErrAuthenticationThrottled = ErrBreakGlassThrottled
)

type BreakGlassConfigSource interface {
	Load(context.Context) (*config.ServerConfig, error)
}

type BreakGlassConfigSourceFunc func(context.Context) (*config.ServerConfig, error)

func (source BreakGlassConfigSourceFunc) Load(ctx context.Context) (*config.ServerConfig, error) {
	return source(ctx)
}

type fileBreakGlassConfigSource struct{ path string }

func (source fileBreakGlassConfigSource) Load(ctx context.Context) (*config.ServerConfig, error) {
	if err := ctx.Err(); err != nil {
		return nil, err
	}
	return config.LoadServerConfig(source.path)
}

type BreakGlassThrottleOptions struct {
	// MaxSources bounds the source-key map. A source is the untrusted peer
	// address, never an X-Forwarded-For value.
	MaxSources int
	// MaxSourceEntries is accepted as a descriptive alias for MaxSources.
	MaxSourceEntries int

	MaxArgon2Concurrency  int
	FailuresBeforeLockout int
	LockoutDuration       time.Duration
	BaseDelay             time.Duration
	MaxDelay              time.Duration
}

type BreakGlassOptions struct {
	// ConfigSource is consulted for every login and Authenticate call. Config
	// is a convenient static/injectable source for tests; ConfigPath is the
	// production-friendly live file source.
	Config       *config.ServerConfig
	ConfigSource BreakGlassConfigSource
	ConfigPath   string
	Secrets      secretmount.Reader
	Now          func() time.Time
	Throttle     BreakGlassThrottleOptions
}

type BreakGlassLoginRequest struct {
	Username string `json:"username"`
	Password string `json:"password"`
}

type BreakGlassCredential struct {
	Generation string
	Verifier   string
}

type breakGlassVerifier struct {
	raw  string
	salt []byte
	hash []byte
}

type breakGlassState struct {
	config     *config.ServerConfig
	credential BreakGlassCredential
	verifier   breakGlassVerifier
	revision   string
}

type BreakGlassService struct {
	configSource BreakGlassConfigSource
	secrets      secretmount.Reader
	cookies      *cookieCodec
	now          func() time.Time
	throttle     *breakGlassThrottle
	argon2       chan struct{}
}

// BreakGlass is retained as a concise integration name without hiding the
// concrete service's exported options and methods.
type BreakGlass = BreakGlassService
type BreakGlassAuthenticator = BreakGlassService

func NewBreakGlass(options BreakGlassOptions) (*BreakGlassService, error) {
	source, initial, err := newBreakGlassConfigSource(options)
	if err != nil {
		return nil, err
	}
	if initial == nil {
		return nil, errors.New("break-glass server config is nil")
	}
	if err := initial.ValidateBreakGlass(); err != nil {
		return nil, fmt.Errorf("validate break-glass config: %w", err)
	}
	if !initial.BreakGlass.Enabled {
		return nil, ErrBreakGlassDisabled
	}

	secrets := options.Secrets
	if secrets == nil {
		secrets, err = secretmount.NewMountedReader(initial.OIDC.SecretMountRoot, secretmount.DefaultMaxBytes)
		if err != nil {
			return nil, fmt.Errorf("open break-glass secret mounts: %w", err)
		}
	}
	keys, err := newKeyRingSource(secrets, initial.OIDC.SessionSecret)
	if err != nil {
		return nil, err
	}
	throttle, err := newBreakGlassThrottle(options.Throttle)
	if err != nil {
		return nil, err
	}
	maxConcurrency := normalizedArgon2Concurrency(options.Throttle.MaxArgon2Concurrency)
	return &BreakGlassService{
		configSource: source,
		secrets:      secrets,
		cookies:      newCookieCodec(keys, options.Now),
		now:          normalizeClock(options.Now),
		throttle:     throttle,
		argon2:       make(chan struct{}, maxConcurrency),
	}, nil
}

func NewBreakGlassService(options BreakGlassOptions) (*BreakGlassService, error) {
	return NewBreakGlass(options)
}

func NewBreakGlassAuthenticator(options BreakGlassOptions) (*BreakGlassService, error) {
	return NewBreakGlass(options)
}

func newBreakGlassConfigSource(options BreakGlassOptions) (BreakGlassConfigSource, *config.ServerConfig, error) {
	if options.ConfigSource != nil {
		initial, err := options.ConfigSource.Load(context.Background())
		if err != nil {
			return nil, nil, fmt.Errorf("load break-glass config: %w", err)
		}
		return options.ConfigSource, initial, nil
	}
	path := options.ConfigPath
	if path != "" {
		source := fileBreakGlassConfigSource{path: path}
		initial, err := source.Load(context.Background())
		if err != nil {
			return nil, nil, fmt.Errorf("load break-glass config: %w", err)
		}
		return source, initial, nil
	}
	if options.Config == nil {
		return nil, nil, errors.New("break-glass config source is required")
	}
	// The pointer is intentionally used as an injectable live source for small
	// embedders and tests. Production wiring can use ConfigPath or ConfigSource
	// to obtain an atomic file/object snapshot.
	source := BreakGlassConfigSourceFunc(func(context.Context) (*config.ServerConfig, error) { return options.Config, nil })
	return source, options.Config, nil
}

func normalizeClock(now func() time.Time) func() time.Time {
	if now == nil {
		return time.Now
	}
	return now
}

func normalizedArgon2Concurrency(value int) int {
	if value <= 0 {
		return 2
	}
	if value > 8 {
		return 8
	}
	return value
}

// Login is the explicit browser entry point. It intentionally accepts only a
// same-origin POST and creates the one shared application session cookie; it
// does not redirect to or fall back to OIDC.
func (service *BreakGlassService) Login(w http.ResponseWriter, request *http.Request) error {
	if service == nil || request == nil {
		return ErrBreakGlassInvalidRequest
	}
	if request.Method != http.MethodPost {
		return ErrBreakGlassMethodNotAllowed
	}
	if request.URL.RawQuery != "" || request.URL.Fragment != "" {
		return ErrBreakGlassInvalidRequest
	}
	if len(request.Header.Values("Authorization")) != 0 {
		return ErrAuthenticationConflict
	}
	if hasNamedCookie(request, SessionCookieName) {
		return ErrAuthenticationConflict
	}
	if err := service.validSameOriginRequest(request); err != nil {
		return err
	}
	input, err := decodeBreakGlassLoginInput(request)
	if err != nil {
		return err
	}
	encoded, expires, err := service.authenticateCredentials(request.Context(), requestSource(request), input.Username, input.Password)
	if err != nil {
		return err
	}
	setProtectedCookie(w, SessionCookieName, encoded, expires)
	http.Redirect(w, request, "/", http.StatusSeeOther)
	return nil
}

// BeginLogin is an integration alias. Unlike BrowserOIDC.BeginLogin, this
// method is deliberately POST-only because break-glass is never an implicit
// browser fallback.
func (service *BreakGlassService) BeginLogin(w http.ResponseWriter, request *http.Request) error {
	return service.Login(w, request)
}

// AuthenticateCredentials is the non-HTTP seam for a future server adapter.
// The returned value is a protected shared session cookie, never a bearer
// token. The source is intentionally not caller-controlled by this method.
func (service *BreakGlassService) AuthenticateCredentials(ctx context.Context, username, password string) (string, time.Time, error) {
	return service.authenticateCredentials(ctx, "internal", username, password)
}

func (service *BreakGlassService) authenticateCredentials(ctx context.Context, source, username, password string) (string, time.Time, error) {
	state, err := service.loadState(ctx)
	if err != nil {
		return "", time.Time{}, ErrBreakGlassAuthenticationFailed
	}
	if len(username) == 0 || len(username) > 128 || len(password) > BreakGlassPasswordMaxBytes {
		return "", time.Time{}, ErrBreakGlassAuthenticationFailed
	}
	if source == "" {
		source = "unknown"
	}
	if throttled, delay := service.throttle.check(service.now(), source); throttled {
		return "", time.Time{}, ErrBreakGlassThrottled
	} else if delay > 0 {
		if err := waitBreakGlassDelay(ctx, delay); err != nil {
			return "", time.Time{}, ErrBreakGlassThrottled
		}
	}

	select {
	case service.argon2 <- struct{}{}:
		defer func() { <-service.argon2 }()
	default:
		return "", time.Time{}, ErrBreakGlassThrottled
	}
	passwordBytes := []byte(password)
	derived := argon2.IDKey(passwordBytes, state.verifier.salt, breakGlassArgonTime, breakGlassArgonMemory, breakGlassArgonThreads, breakGlassArgonHashBytes)
	clearBytes(passwordBytes)
	hashMatches := subtle.ConstantTimeCompare(derived, state.verifier.hash)
	usernameMatches := constantTimeStringEqual(username, state.config.BreakGlass.Username)
	clearBytes(derived)
	matches := hashMatches&usernameMatches == 1
	if !matches {
		if service.throttle.failure(service.now(), source) {
			return "", time.Time{}, ErrBreakGlassThrottled
		}
		return "", time.Time{}, ErrBreakGlassAuthenticationFailed
	}

	now := service.now().UTC()
	expires := now.Add(BreakGlassSessionLifetime)
	payload := sessionPayload{
		Version:   "v1",
		Actor:     Actor{Subject: state.config.BreakGlass.Username, Roles: []Role{RoleAdministrator}, Method: MethodBreakGlass},
		Method:    MethodBreakGlass,
		Revision:  state.revision,
		IssuedAt:  now.Unix(),
		ExpiresAt: expires.Unix(),
	}
	encoded, err := service.cookies.encode(ctx, "session", payload)
	if err != nil {
		return "", time.Time{}, ErrBreakGlassAuthenticationFailed
	}
	service.throttle.success(source)
	return encoded, expires, nil
}

func (service *BreakGlassService) Authenticate(request *http.Request) (Actor, error) {
	if service == nil || request == nil {
		return Actor{}, ErrAuthenticationRequired
	}
	// Load both live inputs before inspecting the cookie. This intentionally
	// fails closed on a Secret/config rotation even for a previously valid
	// emergency session.
	state, err := service.loadState(request.Context())
	if err != nil {
		return Actor{}, ErrBreakGlassAuthenticationFailed
	}
	if len(request.Header.Values("Authorization")) != 0 {
		return Actor{}, ErrAuthenticationConflict
	}
	encoded, err := readUniqueCookie(request, SessionCookieName)
	if errors.Is(err, ErrAuthenticationConflict) {
		return Actor{}, err
	}
	if err != nil {
		return Actor{}, ErrAuthenticationRequired
	}
	var payload sessionPayload
	if err := service.cookies.decodeCurrent(request.Context(), "session", encoded, &payload); err != nil {
		return Actor{}, ErrInvalidAuthentication
	}
	now := service.now().UTC()
	if payload.Version != "v1" || payload.Method != MethodBreakGlass || payload.Revision == "" || !constantTimeEqual(payload.Revision, state.revision) || payload.ExpiresAt-payload.IssuedAt != int64(BreakGlassSessionLifetime/time.Second) || !validAbsoluteTimes(now, payload.IssuedAt, payload.ExpiresAt, BreakGlassSessionLifetime) {
		if payload.ExpiresAt <= now.Unix() {
			return Actor{}, ErrSessionExpired
		}
		return Actor{}, ErrInvalidAuthentication
	}
	payload.Actor.Method = payload.Method
	actor, err := payload.Actor.Normalized()
	if err != nil || actor.Method != MethodBreakGlass || len(actor.Roles) != 1 || actor.Roles[0] != RoleAdministrator || !constantTimeEqual(actor.Subject, state.config.BreakGlass.Username) {
		return Actor{}, ErrInvalidAuthentication
	}
	return actor, nil
}

func (service *BreakGlassService) loadState(ctx context.Context) (breakGlassState, error) {
	if service == nil || service.configSource == nil || service.secrets == nil {
		return breakGlassState{}, errors.New("break-glass service is unavailable")
	}
	if err := ctx.Err(); err != nil {
		return breakGlassState{}, err
	}
	live, err := service.configSource.Load(ctx)
	if err != nil || live == nil || !live.BreakGlass.Enabled {
		return breakGlassState{}, errors.New("break-glass configuration is unavailable")
	}
	if err := live.ValidateBreakGlass(); err != nil {
		return breakGlassState{}, errors.New("break-glass configuration is invalid")
	}
	contents, err := service.secrets.Read(ctx, live.BreakGlass.CredentialSecret)
	if err != nil {
		return breakGlassState{}, errors.New("break-glass credential is unavailable")
	}
	credential, verifier, err := parseBreakGlassCredential(contents)
	clearBytes(contents)
	if err != nil {
		return breakGlassState{}, errors.New("break-glass credential is invalid")
	}
	return breakGlassState{config: live, credential: credential, verifier: verifier, revision: breakGlassRevision(live.BreakGlass.Username, credential)}, nil
}

func (service *BreakGlassService) validSameOriginRequest(request *http.Request) error {
	origins := request.Header.Values("Origin")
	if len(origins) != 1 {
		return ErrBreakGlassInvalidRequest
	}
	origin, err := parseStrictOrigin(origins[0])
	if err != nil {
		return ErrBreakGlassInvalidRequest
	}
	live, err := service.configSource.Load(request.Context())
	if err != nil || live == nil {
		return ErrBreakGlassAuthenticationFailed
	}
	public, err := url.Parse(live.PublicURL)
	if err != nil || public.Host == "" || public.User != nil || public.Path != "" && public.Path != "/" || public.RawQuery != "" || public.Fragment != "" || !sameWebOrigin(origin, public) {
		return ErrBreakGlassInvalidRequest
	}
	// An absolute request target carries an independently checkable origin.
	// Relative server requests are intentionally checked by Origin only: TLS
	// termination and trusted proxy normalization belong to the HTTP adapter,
	// not this authentication seam.
	if request.URL.IsAbs() && request.URL.Host != "" && !sameWebOrigin(&url.URL{Scheme: request.URL.Scheme, Host: request.URL.Host}, public) {
		return ErrBreakGlassInvalidRequest
	}
	return nil
}

func parseStrictOrigin(raw string) (*url.URL, error) {
	parsed, err := url.Parse(raw)
	if err != nil || parsed.Scheme == "" || parsed.Host == "" || parsed.User != nil || parsed.Path != "" || parsed.RawQuery != "" || parsed.Fragment != "" {
		return nil, errors.New("origin is invalid")
	}
	return parsed, nil
}

func decodeBreakGlassLoginInput(request *http.Request) (BreakGlassLoginRequest, error) {
	if request.ContentLength > BreakGlassLoginBodyMaxBytes {
		return BreakGlassLoginRequest{}, ErrBreakGlassInvalidRequest
	}
	if request.Body == nil {
		return BreakGlassLoginRequest{}, ErrBreakGlassInvalidRequest
	}
	body, err := io.ReadAll(io.LimitReader(request.Body, BreakGlassLoginBodyMaxBytes+1))
	if err != nil || len(body) > BreakGlassLoginBodyMaxBytes {
		return BreakGlassLoginRequest{}, ErrBreakGlassInvalidRequest
	}
	mediaType, _, err := mime.ParseMediaType(request.Header.Get("Content-Type"))
	if err != nil {
		return BreakGlassLoginRequest{}, ErrBreakGlassInvalidRequest
	}
	switch mediaType {
	case "application/json":
		var input BreakGlassLoginRequest
		decoder := json.NewDecoder(strings.NewReader(string(body)))
		decoder.DisallowUnknownFields()
		if err := decoder.Decode(&input); err != nil {
			return BreakGlassLoginRequest{}, ErrBreakGlassInvalidRequest
		}
		var extra any
		if err := decoder.Decode(&extra); err != io.EOF {
			return BreakGlassLoginRequest{}, ErrBreakGlassInvalidRequest
		}
		if len(input.Username) > 128 || len(input.Password) > BreakGlassPasswordMaxBytes {
			return BreakGlassLoginRequest{}, ErrBreakGlassAuthenticationFailed
		}
		return input, nil
	case "application/x-www-form-urlencoded":
		values, err := url.ParseQuery(string(body))
		if err != nil || len(values) != 2 || len(values["username"]) != 1 || len(values["password"]) != 1 {
			return BreakGlassLoginRequest{}, ErrBreakGlassInvalidRequest
		}
		for key := range values {
			if key != "username" && key != "password" {
				return BreakGlassLoginRequest{}, ErrBreakGlassInvalidRequest
			}
		}
		input := BreakGlassLoginRequest{Username: values.Get("username"), Password: values.Get("password")}
		if len(input.Username) > 128 || len(input.Password) > BreakGlassPasswordMaxBytes {
			return BreakGlassLoginRequest{}, ErrBreakGlassAuthenticationFailed
		}
		return input, nil
	default:
		return BreakGlassLoginRequest{}, ErrBreakGlassInvalidRequest
	}
}

func parseBreakGlassCredential(contents []byte) (BreakGlassCredential, breakGlassVerifier, error) {
	if len(contents) == 0 || len(contents) > BreakGlassCredentialDocumentMaxBytes {
		return BreakGlassCredential{}, breakGlassVerifier{}, errors.New("credential document is invalid")
	}
	if contents[len(contents)-1] == '\n' {
		contents = contents[:len(contents)-1]
	}
	if len(contents) == 0 || strings.ContainsRune(string(contents), '\r') {
		return BreakGlassCredential{}, breakGlassVerifier{}, errors.New("credential document is invalid")
	}
	lines := strings.Split(string(contents), "\n")
	if len(lines) != 3 || lines[0] != breakGlassCredentialHeader {
		return BreakGlassCredential{}, breakGlassVerifier{}, errors.New("credential document is invalid")
	}
	generation, ok := exactCredentialField(lines[1], "generation")
	if !ok || len(generation) > BreakGlassGenerationMaxBytes*2 {
		return BreakGlassCredential{}, breakGlassVerifier{}, errors.New("credential document is invalid")
	}
	generationBytes, err := base64.RawURLEncoding.Strict().DecodeString(generation)
	if err != nil || len(generationBytes) < 16 || len(generationBytes) > BreakGlassGenerationMaxBytes {
		return BreakGlassCredential{}, breakGlassVerifier{}, errors.New("credential document is invalid")
	}
	verifierRaw, ok := exactCredentialField(lines[2], "verifier")
	if !ok || len(verifierRaw) == 0 || len(verifierRaw) > BreakGlassVerifierMaxBytes {
		return BreakGlassCredential{}, breakGlassVerifier{}, errors.New("credential document is invalid")
	}
	verifier, err := parseBreakGlassVerifier(verifierRaw)
	if err != nil {
		return BreakGlassCredential{}, breakGlassVerifier{}, errors.New("credential document is invalid")
	}
	return BreakGlassCredential{Generation: generation, Verifier: verifierRaw}, verifier, nil
}

func ParseBreakGlassCredential(contents []byte) (BreakGlassCredential, error) {
	credential, _, err := parseBreakGlassCredential(contents)
	return credential, err
}

func ParseBreakGlassCredentialDocument(contents []byte) (BreakGlassCredential, error) {
	return ParseBreakGlassCredential(contents)
}

func exactCredentialField(line, name string) (string, bool) {
	parts := strings.Split(line, " ")
	return func() (string, bool) {
		if len(parts) != 2 || parts[0] != name || parts[1] == "" || strings.TrimSpace(parts[1]) != parts[1] {
			return "", false
		}
		return parts[1], true
	}()
}

func parseBreakGlassVerifier(raw string) (breakGlassVerifier, error) {
	if len(raw) > BreakGlassVerifierMaxBytes {
		return breakGlassVerifier{}, errors.New("verifier is too large")
	}
	parts := strings.Split(raw, "$")
	if len(parts) != 6 || parts[0] != "" || parts[1] != "argon2id" || parts[2] != "v=19" || parts[3] != "m=65536,t=3,p=1" {
		return breakGlassVerifier{}, errors.New("verifier is not the pinned Argon2id PHC form")
	}
	salt, err := decodePHCPart(parts[4], breakGlassArgonSaltBytes)
	if err != nil {
		return breakGlassVerifier{}, err
	}
	hash, err := decodePHCPart(parts[5], breakGlassArgonHashBytes)
	if err != nil {
		return breakGlassVerifier{}, err
	}
	return breakGlassVerifier{raw: raw, salt: salt, hash: hash}, nil
}

func decodePHCPart(raw string, size int) ([]byte, error) {
	encodedLength := base64.RawStdEncoding.EncodedLen(size)
	if len(raw) != encodedLength {
		return nil, errors.New("PHC base64 is invalid")
	}
	// Argon2's PHC alphabet is ./0-9A-Za-z, rather than the standard
	// base64 alphabet. Convert its six-bit indices to the Go decoder's
	// alphabet and reject all other spellings (including padding and URL-safe
	// characters).
	const phcAlphabet = "./0123456789ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz"
	const stdAlphabet = "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/"
	var converted strings.Builder
	converted.Grow(len(raw))
	for _, char := range raw {
		index := strings.IndexRune(phcAlphabet, char)
		if index < 0 {
			return nil, errors.New("PHC base64 is invalid")
		}
		converted.WriteByte(stdAlphabet[index])
	}
	decoded, err := base64.RawStdEncoding.Strict().DecodeString(converted.String())
	if err != nil || len(decoded) != size {
		return nil, errors.New("PHC base64 is invalid")
	}
	return decoded, nil
}

func breakGlassRevision(username string, credential BreakGlassCredential) string {
	hash := sha256.New()
	hash.Write([]byte(breakGlassRevisionHeader))
	writeRevisionPart := func(value []byte) {
		var length [8]byte
		binary.BigEndian.PutUint64(length[:], uint64(len(value)))
		hash.Write(length[:])
		hash.Write(value)
	}
	writeRevisionPart([]byte(username))
	writeRevisionPart([]byte(credential.Verifier))
	writeRevisionPart([]byte(credential.Generation))
	hash.Write([]byte{1})
	return hex.EncodeToString(hash.Sum(nil))
}

func constantTimeStringEqual(left, right string) int {
	length := len(left)
	if len(right) > length {
		length = len(right)
	}
	difference := len(left) ^ len(right)
	for index := 0; index < length; index++ {
		var leftByte, rightByte byte
		if index < len(left) {
			leftByte = left[index]
		}
		if index < len(right) {
			rightByte = right[index]
		}
		difference |= int(leftByte ^ rightByte)
	}
	return subtle.ConstantTimeEq(int32(difference), 0)
}

func clearBytes(value []byte) {
	for index := range value {
		value[index] = 0
	}
}

func requestSource(request *http.Request) string {
	if request == nil {
		return "unknown"
	}
	value := request.RemoteAddr
	if host, _, err := net.SplitHostPort(value); err == nil {
		value = host
	}
	if value == "" || len(value) > 128 {
		return "unknown"
	}
	return value
}

func waitBreakGlassDelay(ctx context.Context, delay time.Duration) error {
	timer := time.NewTimer(delay)
	defer timer.Stop()
	select {
	case <-timer.C:
		return nil
	case <-ctx.Done():
		return ctx.Err()
	}
}

type breakGlassThrottleState struct {
	failures   int
	lockedTill time.Time
	lastSeen   time.Time
}

type breakGlassThrottle struct {
	mu      sync.Mutex
	global  breakGlassThrottleState
	sources map[string]breakGlassThrottleState
	options BreakGlassThrottleOptions
}

func newBreakGlassThrottle(options BreakGlassThrottleOptions) (*breakGlassThrottle, error) {
	maxSources := options.MaxSources
	if maxSources == 0 {
		maxSources = options.MaxSourceEntries
	}
	if maxSources == 0 {
		maxSources = 1024
	}
	if maxSources < 1 || maxSources > 4096 {
		return nil, errors.New("break-glass source throttle bound is invalid")
	}
	if options.MaxArgon2Concurrency < 0 || options.MaxArgon2Concurrency > 8 {
		return nil, errors.New("break-glass Argon2 concurrency bound is invalid")
	}
	if options.FailuresBeforeLockout == 0 {
		options.FailuresBeforeLockout = 5
	}
	if options.FailuresBeforeLockout < 1 || options.FailuresBeforeLockout > 100 {
		return nil, errors.New("break-glass lockout threshold is invalid")
	}
	if options.LockoutDuration == 0 {
		options.LockoutDuration = 30 * time.Second
	}
	if options.BaseDelay == 0 {
		options.BaseDelay = 25 * time.Millisecond
	}
	if options.MaxDelay == 0 {
		options.MaxDelay = time.Second
	}
	if options.LockoutDuration < 0 || options.LockoutDuration > 24*time.Hour || options.BaseDelay < 0 || options.MaxDelay < options.BaseDelay || options.MaxDelay > time.Minute {
		return nil, errors.New("break-glass throttle duration is invalid")
	}
	options.MaxSources = maxSources
	return &breakGlassThrottle{sources: make(map[string]breakGlassThrottleState, maxSources), options: options}, nil
}

func (throttle *breakGlassThrottle) check(now time.Time, source string) (bool, time.Duration) {
	throttle.mu.Lock()
	defer throttle.mu.Unlock()
	global := throttle.global
	state, ok := throttle.sources[source]
	if ok {
		state.lastSeen = now
		throttle.sources[source] = state
	}
	if global.lockedTill.After(now) || state.lockedTill.After(now) {
		return true, 0
	}
	return false, maxBreakGlassDelay(throttle.options, global.failures, state.failures)
}

func (throttle *breakGlassThrottle) failure(now time.Time, source string) bool {
	throttle.mu.Lock()
	defer throttle.mu.Unlock()
	throttle.global = registerBreakGlassFailure(throttle.global, now, throttle.options)
	state, ok := throttle.sources[source]
	if !ok && len(throttle.sources) >= throttle.options.MaxSources {
		oldest := ""
		var oldestTime time.Time
		for key, candidate := range throttle.sources {
			if oldest == "" || candidate.lastSeen.Before(oldestTime) {
				oldest, oldestTime = key, candidate.lastSeen
			}
		}
		delete(throttle.sources, oldest)
	}
	state = registerBreakGlassFailure(state, now, throttle.options)
	throttle.sources[source] = state
	return throttle.global.lockedTill.After(now) || state.lockedTill.After(now)
}

func registerBreakGlassFailure(state breakGlassThrottleState, now time.Time, options BreakGlassThrottleOptions) breakGlassThrottleState {
	state.failures++
	state.lastSeen = now
	if state.failures >= options.FailuresBeforeLockout {
		state.lockedTill = now.Add(options.LockoutDuration)
	}
	return state
}

func (throttle *breakGlassThrottle) success(source string) {
	throttle.mu.Lock()
	defer throttle.mu.Unlock()
	throttle.global = breakGlassThrottleState{}
	delete(throttle.sources, source)
}

func maxBreakGlassDelay(options BreakGlassThrottleOptions, counts ...int) time.Duration {
	maximum := 0
	for _, count := range counts {
		if count > maximum {
			maximum = count
		}
	}
	if maximum <= 0 || options.BaseDelay == 0 {
		return 0
	}
	delay := options.BaseDelay
	for index := 1; index < maximum && delay < options.MaxDelay; index++ {
		if delay > options.MaxDelay/2 {
			delay = options.MaxDelay
		} else {
			delay *= 2
		}
	}
	if delay > options.MaxDelay {
		return options.MaxDelay
	}
	return delay
}
