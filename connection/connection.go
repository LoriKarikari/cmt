package connection

import (
	"bufio"
	"context"
	"crypto/x509"
	"encoding/pem"
	"errors"
	"fmt"
	"io"
	"io/fs"
	"net"
	"os"
	"path/filepath"
	"regexp"
	"strings"
	"sync"
	"time"

	"github.com/go-playground/validator/v10"
	"golang.org/x/crypto/ssh"
	"golang.org/x/crypto/ssh/knownhosts"
	"golang.org/x/net/idna"
	"golang.org/x/time/rate"
)

type ConnectionError struct {
	Op   string
	Err  error
	Host string
}

func (e *ConnectionError) Error() string {
	if e.Host != "" {
		return fmt.Sprintf("connection error [%s@%s]: %s: %v", e.Op, e.Host, e.Op, e.Err)
	}
	return fmt.Sprintf("connection error [%s]: %v", e.Op, e.Err)
}

func (e *ConnectionError) Unwrap() error {
	return e.Err
}

type ValidationError struct {
	Field   string
	Value   interface{}
	Message string
}

func (e *ValidationError) Error() string {
	return fmt.Sprintf("validation error: %s: %s", e.Field, e.Message)
}

var (
	ErrInvalidConfig    = errors.New("invalid configuration")
	ErrConnectionFailed = errors.New("connection failed")
	ErrSessionFailed    = errors.New("session creation failed")
	ErrCommandFailed    = errors.New("command execution failed")
	ErrTransferFailed   = errors.New("file transfer failed")
	ErrInvalidKey       = errors.New("invalid key")
	ErrUnsafeCommand    = errors.New("unsafe command")
	ErrInvalidPath      = errors.New("invalid path")
)

type Connection interface {
	Execute(ctx context.Context, command string) (*Result, error)
	ExecuteArgs(ctx context.Context, cmd string, args ...string) (*Result, error)
	Upload(ctx context.Context, localPath, remotePath string, mode fs.FileMode) error
	Download(ctx context.Context, remotePath, localPath string) error
	Close() error
}

type Result struct {
	Stdout   string
	Stderr   string
	ExitCode int
}

type Config struct {
	Host                 string        `validate:"required,hostaddr"`
	Port                 int           `validate:"min=1,max=65535"`
	User                 string        `validate:"required,username,max=32"`
	Password             string        `validate:"omitempty"`
	KeyPath              string        `validate:"omitempty"`
	KeyData              []byte        `validate:"omitempty"`
	Timeout              time.Duration `validate:"min=1s,max=10m"`
	KnownHostsPath       string        `validate:"omitempty"`
	AllowInsecureHostKey bool          `validate:"-"`

	cachedSigner ssh.Signer `validate:"-"`
	cacheValid   bool       `validate:"-"`
}

const (
	maxOutputSize   = 10 * 1024 * 1024
	maxKeyFileSize  = 32 * 1024
	bufferSize      = 64 * 1024
	maxTransferSize = 100 * 1024 * 1024

	defaultFailureThreshold = 5
	defaultTimeout          = 60 * time.Second
	defaultMaxRetries       = 3

	defaultRateLimit      = 10
	defaultBurstLimit     = 20
	defaultRequestTimeout = 30 * time.Second
)

var (
	validate      *validator.Validate
	validatorOnce sync.Once

	regexOnce     sync.Once
	hostnameRegex *regexp.Regexp
	usernameRegex *regexp.Regexp

	safeCommandRegex = regexp.MustCompile(`^[a-zA-Z0-9\-._/ ]+$`)
)

func initRegexes() {
	hostnameRegex = regexp.MustCompile(`^[a-zA-Z0-9]([a-zA-Z0-9\-]{0,61}[a-zA-Z0-9])?(\.[a-zA-Z0-9]([a-zA-Z0-9\-]{0,61}[a-zA-Z0-9])?)*$`)
	usernameRegex = regexp.MustCompile(`^[a-zA-Z_][a-zA-Z0-9_-]*$`)
}

func initValidator() {
	validate = validator.New(validator.WithRequiredStructEnabled())
	validate.RegisterValidation("username", validateUsernameTag)
	validate.RegisterValidation("hostaddr", validateHostTag)
	validate.RegisterStructValidation(validateAuth, Config{})
	validate.RegisterStructValidation(validateKeyPath, Config{})
	validate.RegisterStructValidation(validateKeyData, Config{})
}

func NewConfig(host, user string) *Config {
	return &Config{
		Host:    host,
		Port:    22,
		User:    user,
		Timeout: 30 * time.Second,
	}
}

func (r *Result) Success() bool {
	return r.ExitCode == 0
}

func (c *Config) AuthMethod() string {
	if c.Password != "" {
		return "password"
	}
	if c.KeyPath != "" {
		return "keyfile"
	}
	if len(c.KeyData) > 0 {
		return "keydata"
	}
	return "none"
}

func (c *Config) String() string {
	return fmt.Sprintf("Config{Host:%s, Port:%d, User:%s, Auth:%s, Timeout:%v}",
		c.Host, c.Port, c.User, c.AuthMethod(), c.Timeout)
}

func (c *Config) getSigner() (ssh.Signer, error) {
	if c.cacheValid && c.cachedSigner != nil {
		return c.cachedSigner, nil
	}

	var data []byte
	var err error

	if len(c.KeyData) > 0 {
		data = c.KeyData
	} else if c.KeyPath != "" {
		data, err = os.ReadFile(c.KeyPath)
		if err != nil {
			return nil, fmt.Errorf("unable to read key file: %v", err)
		}
		defer clearBytes(data)
	} else {
		return nil, errors.New("no key data available")
	}

	signer, err := parsePrivateKey(data)
	if err != nil {
		return nil, err
	}

	c.cachedSigner = signer
	c.cacheValid = true
	return signer, nil
}

func (c *Config) ClearSensitiveData() {
	if c.Password != "" {
		passwordBytes := []byte(c.Password)
		clearBytes(passwordBytes)
		c.Password = ""
	}
	if len(c.KeyData) > 0 {
		clearBytes(c.KeyData)
		c.KeyData = nil
	}
	c.cachedSigner = nil
	c.cacheValid = false
}

func (c *Config) Validate() error {
	validatorOnce.Do(initValidator)
	return validate.Struct(c)
}

func validateUsernameTag(fl validator.FieldLevel) bool {
	regexOnce.Do(initRegexes)
	return usernameRegex.MatchString(fl.Field().String())
}

func validateHostTag(fl validator.FieldLevel) bool {
	regexOnce.Do(initRegexes)
	host := strings.TrimSpace(fl.Field().String())
	if strings.Contains(host, ":") && !strings.HasPrefix(host, "[") {
		return false
	}
	if ip := net.ParseIP(host); ip != nil {
		return true
	}
	if strings.HasPrefix(host, "[") && strings.HasSuffix(host, "]") {
		ipv6 := host[1 : len(host)-1]
		if idx := strings.Index(ipv6, "%"); idx != -1 {
			ipv6 = ipv6[:idx]
		}
		if ip := net.ParseIP(ipv6); ip != nil && ip.To4() == nil {
			return true
		}
		return false
	}
	asciiHost, err := idna.ToASCII(host)
	if err != nil {
		return false
	}
	return hostnameRegex.MatchString(asciiHost) && len(asciiHost) <= 253
}

func validateAuth(sl validator.StructLevel) {
	cfg := sl.Current().Interface().(Config)
	count := 0
	if cfg.Password != "" {
		count++
	}
	if cfg.KeyPath != "" {
		count++
	}
	if len(cfg.KeyData) > 0 {
		count++
	}
	if count == 0 {
		sl.ReportError(cfg, "Auth", "Auth", "required", "")
	}
	if count > 1 {
		sl.ReportError(cfg, "Auth", "Auth", "exactlyoneauth", "")
	}
}

func validateKeyPath(sl validator.StructLevel) {
	cfg := sl.Current().Interface().(Config)
	if cfg.KeyPath == "" {
		return
	}
	keyPath := cfg.KeyPath
	if strings.HasPrefix(keyPath, "~/") {
		home, err := os.UserHomeDir()
		if err != nil {
			sl.ReportError(cfg.KeyPath, "KeyPath", "KeyPath", "keypath", "home")
			return
		}
		keyPath = filepath.Join(home, keyPath[2:])
	}
	keyPath = filepath.Clean(keyPath)
	abs, err := filepath.Abs(keyPath)
	if err != nil {
		sl.ReportError(cfg.KeyPath, "KeyPath", "KeyPath", "keypath", "abs")
		return
	}
	home, _ := os.UserHomeDir()
	if !strings.HasPrefix(abs, filepath.Join(home, ".ssh")) {
		sl.ReportError(cfg.KeyPath, "KeyPath", "KeyPath", "keypath", "outside")
		return
	}
	info, err := os.Stat(abs)
	if err != nil || info.IsDir() {
		sl.ReportError(cfg.KeyPath, "KeyPath", "KeyPath", "keypath", "noaccess")
		return
	}
	if info.Size() > maxKeyFileSize {
		sl.ReportError(cfg.KeyPath, "KeyPath", "KeyPath", "keypath", "toolarge")
		return
	}
	if info.Mode().Perm()&0o077 != 0 {
		sl.ReportError(cfg.KeyPath, "KeyPath", "KeyPath", "keypath", "perms")
		return
	}
	configPtr := &cfg
	_, err = configPtr.getSigner()
	if err != nil {
		sl.ReportError(cfg.KeyPath, "KeyPath", "KeyPath", "keypath", "invalid")
	}
}

func validateKeyData(sl validator.StructLevel) {
	cfg := sl.Current().Interface().(Config)
	if len(cfg.KeyData) == 0 {
		return
	}
	if len(cfg.KeyData) > maxKeyFileSize {
		sl.ReportError(cfg.KeyData, "KeyData", "KeyData", "keydata", "toolarge")
		return
	}
	configPtr := &cfg
	_, err := configPtr.getSigner()
	if err != nil {
		sl.ReportError(cfg.KeyData, "KeyData", "KeyData", "keydata", "invalid")
	}
}

func parsePrivateKey(data []byte) (ssh.Signer, error) {
	if signer, err := ssh.ParsePrivateKey(data); err == nil {
		return signer, nil
	}
	block, _ := pem.Decode(data)
	if block == nil {
		return nil, errors.New("invalid key format")
	}
	if _, err := x509.ParsePKCS1PrivateKey(block.Bytes); err == nil {
		return ssh.ParsePrivateKey(pem.EncodeToMemory(block))
	}
	if _, err := x509.ParsePKCS8PrivateKey(block.Bytes); err == nil {
		return ssh.ParsePrivateKey(pem.EncodeToMemory(block))
	}
	if _, err := x509.ParseECPrivateKey(block.Bytes); err == nil {
		return ssh.ParsePrivateKey(pem.EncodeToMemory(block))
	}
	return nil, errors.New("unsupported key type")
}

func clearBytes(b []byte) {
	for i := range b {
		b[i] = 0
	}
}

type SecureBytes struct {
	data []byte
}

func NewSecureBytes(data []byte) *SecureBytes {
	return &SecureBytes{data: data}
}

func (s *SecureBytes) Bytes() []byte {
	return s.data
}

func (s *SecureBytes) Clear() {
	if s.data != nil {
		clearBytes(s.data)
		s.data = nil
	}
}

func (s *SecureBytes) Copy() *SecureBytes {
	if s.data == nil {
		return &SecureBytes{}
	}
	copied := make([]byte, len(s.data))
	copy(copied, s.data)
	return &SecureBytes{data: copied}
}

type CircuitBreaker struct {
	mu               sync.RWMutex
	failureThreshold int
	resetTimeout     time.Duration
	maxRetries       int
	failures         int
	lastFailureTime  time.Time
	state            CircuitState
}

type CircuitState int

const (
	StateClosed CircuitState = iota
	StateOpen
	StateHalfOpen
)

func (s CircuitState) String() string {
	switch s {
	case StateClosed:
		return "CLOSED"
	case StateOpen:
		return "OPEN"
	case StateHalfOpen:
		return "HALF_OPEN"
	default:
		return "UNKNOWN"
	}
}

func NewCircuitBreaker() *CircuitBreaker {
	return &CircuitBreaker{
		failureThreshold: defaultFailureThreshold,
		resetTimeout:     defaultTimeout,
		maxRetries:       defaultMaxRetries,
		state:            StateClosed,
	}
}

func (cb *CircuitBreaker) Call(fn func() error) error {
	cb.mu.Lock()
	defer cb.mu.Unlock()

	if cb.state == StateOpen {
		if time.Since(cb.lastFailureTime) > cb.resetTimeout {
			cb.state = StateHalfOpen
			cb.failures = 0
		} else {
			return &ConnectionError{
				Op:  "circuit breaker",
				Err: errors.New("circuit breaker is OPEN"),
			}
		}
	}

	err := fn()
	if err != nil {
		cb.failures++
		cb.lastFailureTime = time.Now()

		if cb.failures >= cb.failureThreshold {
			cb.state = StateOpen
		}
		return err
	}

	if cb.state == StateHalfOpen {
		cb.state = StateClosed
	}
	cb.failures = 0
	return nil
}

func (cb *CircuitBreaker) State() CircuitState {
	cb.mu.RLock()
	defer cb.mu.RUnlock()
	return cb.state
}

func (cb *CircuitBreaker) Failures() int {
	cb.mu.RLock()
	defer cb.mu.RUnlock()
	return cb.failures
}

type RateLimiter struct {
	limiter *rate.Limiter
	timeout time.Duration
}

func NewRateLimiter() *RateLimiter {
	return &RateLimiter{
		limiter: rate.NewLimiter(rate.Limit(defaultRateLimit), defaultBurstLimit),
		timeout: defaultRequestTimeout,
	}
}

func NewRateLimiterWithConfig(rps float64, burst int, timeout time.Duration) *RateLimiter {
	return &RateLimiter{
		limiter: rate.NewLimiter(rate.Limit(rps), burst),
		timeout: timeout,
	}
}

func (rl *RateLimiter) Wait(ctx context.Context) error {
	waitCtx, cancel := context.WithTimeout(ctx, rl.timeout)
	defer cancel()

	err := rl.limiter.Wait(waitCtx)
	if err != nil {
		if errors.Is(err, context.DeadlineExceeded) {
			return &ConnectionError{
				Op:  "rate limiting",
				Err: errors.New("rate limit timeout exceeded"),
			}
		}
		return &ConnectionError{
			Op:  "rate limiting",
			Err: fmt.Errorf("rate limit error: %v", err),
		}
	}
	return nil
}

func (rl *RateLimiter) Allow() bool {
	return rl.limiter.Allow()
}

func (rl *RateLimiter) SetLimit(rps float64) {
	rl.limiter.SetLimit(rate.Limit(rps))
}

func (rl *RateLimiter) SetBurst(burst int) {
	rl.limiter.SetBurst(burst)
}

func (rl *RateLimiter) Limit() float64 {
	return float64(rl.limiter.Limit())
}

func (rl *RateLimiter) Burst() int {
	return rl.limiter.Burst()
}

type SSHConnection struct {
	client         *ssh.Client
	cfg            *Config
	circuitBreaker *CircuitBreaker
	rateLimiter    *RateLimiter
}

func NewSSHConnection(cfg *Config) (*SSHConnection, error) {
	if cfg == nil {
		return nil, &ValidationError{Field: "config", Message: "config cannot be nil"}
	}
	validatorOnce.Do(initValidator)
	if err := cfg.Validate(); err != nil {
		return nil, fmt.Errorf("%w: %v", ErrInvalidConfig, err)
	}

	authMethods := []ssh.AuthMethod{}
	if cfg.Password != "" {
		authMethods = append(authMethods, ssh.Password(cfg.Password))
	}
	if len(cfg.KeyData) > 0 || cfg.KeyPath != "" {
		signer, err := cfg.getSigner()
		if err != nil {
			return nil, &ConnectionError{
				Op:   "key parsing",
				Err:  fmt.Errorf("%w: %v", ErrInvalidKey, err),
				Host: cfg.Host,
			}
		}
		authMethods = append(authMethods, ssh.PublicKeys(signer))
	}

	hostKeyCallback := ssh.InsecureIgnoreHostKey()
	if !cfg.AllowInsecureHostKey {
		if cfg.KnownHostsPath == "" {
			return nil, &ValidationError{
				Field:   "KnownHostsPath",
				Message: "known_hosts path required when AllowInsecureHostKey is false",
			}
		}
		callback, err := knownhosts.New(cfg.KnownHostsPath)
		if err != nil {
			return nil, &ConnectionError{
				Op:   "loading known_hosts",
				Err:  err,
				Host: cfg.Host,
			}
		}
		hostKeyCallback = callback
	}

	sshCfg := &ssh.ClientConfig{
		User:            cfg.User,
		Auth:            authMethods,
		HostKeyCallback: hostKeyCallback,
		Timeout:         cfg.Timeout,
	}

	addr := net.JoinHostPort(cfg.Host, fmt.Sprintf("%d", cfg.Port))
	client, err := ssh.Dial("tcp", addr, sshCfg)
	if err != nil {
		return nil, &ConnectionError{
			Op:   "dial",
			Err:  fmt.Errorf("%w: %v", ErrConnectionFailed, err),
			Host: cfg.Host,
		}
	}
	return &SSHConnection{
		client:         client,
		cfg:            cfg,
		circuitBreaker: NewCircuitBreaker(),
		rateLimiter:    NewRateLimiter(),
	}, nil
}

func (s *SSHConnection) Close() error {
	err := s.client.Close()
	if s.cfg != nil {
		s.cfg.ClearSensitiveData()
	}
	return err
}

func (s *SSHConnection) CircuitBreakerState() CircuitState {
	return s.circuitBreaker.State()
}

func (s *SSHConnection) CircuitBreakerFailures() int {
	return s.circuitBreaker.Failures()
}

func (s *SSHConnection) RateLimiterStats() (limit float64, burst int) {
	return s.rateLimiter.Limit(), s.rateLimiter.Burst()
}

func (s *SSHConnection) SetRateLimit(rps float64, burst int) {
	s.rateLimiter.SetLimit(rps)
	s.rateLimiter.SetBurst(burst)
}

func isSafeCommand(cmd string) bool {
	return safeCommandRegex.MatchString(cmd)
}

func quoteArg(arg string) string {
	if strings.ContainsAny(arg, " \t\n\"'") {
		return "'" + strings.ReplaceAll(arg, "'", `'\''`) + "'"
	}
	return arg
}

func (s *SSHConnection) Execute(ctx context.Context, command string) (*Result, error) {
	if !isSafeCommand(command) {
		return nil, &ConnectionError{
			Op:   "command validation",
			Err:  fmt.Errorf("%w: %q", ErrUnsafeCommand, command),
			Host: s.cfg.Host,
		}
	}
	return s.ExecuteArgs(ctx, "/bin/sh", "-c", command)
}

func (s *SSHConnection) ExecuteArgs(ctx context.Context, cmd string, args ...string) (*Result, error) {
	if err := s.rateLimiter.Wait(ctx); err != nil {
		return nil, err
	}

	var result *Result
	var execErr error

	err := s.circuitBreaker.Call(func() error {
		result, execErr = s.executeArgsInternal(ctx, cmd, args...)
		return execErr
	})

	if err != nil {
		return nil, err
	}
	return result, nil
}

func (s *SSHConnection) executeArgsInternal(ctx context.Context, cmd string, args ...string) (*Result, error) {
	session, err := s.client.NewSession()
	if err != nil {
		return nil, &ConnectionError{
			Op:   "session creation",
			Err:  fmt.Errorf("%w: %v", ErrSessionFailed, err),
			Host: s.cfg.Host,
		}
	}
	defer session.Close()

	stdout, err := session.StdoutPipe()
	if err != nil {
		return nil, &ConnectionError{
			Op:   "stdout pipe",
			Err:  fmt.Errorf("%w: %v", ErrSessionFailed, err),
			Host: s.cfg.Host,
		}
	}
	stderr, err := session.StderrPipe()
	if err != nil {
		return nil, &ConnectionError{
			Op:   "stderr pipe",
			Err:  fmt.Errorf("%w: %v", ErrSessionFailed, err),
			Host: s.cfg.Host,
		}
	}

	cmdline := cmd
	if len(args) > 0 {
		parts := make([]string, 0, len(args)+1)
		parts = append(parts, cmd)
		parts = append(parts, args...)
		for i := range parts {
			parts[i] = quoteArg(parts[i])
		}
		cmdline = strings.Join(parts, " ")
	}
	if err := session.Start(cmdline); err != nil {
		return nil, &ConnectionError{
			Op:   "command start",
			Err:  fmt.Errorf("%w: %v", ErrCommandFailed, err),
			Host: s.cfg.Host,
		}
	}

	outBuf := &strings.Builder{}
	errBuf := &strings.Builder{}

	var wg sync.WaitGroup
	var copyErr error

	wg.Add(2)
	go func() {
		defer wg.Done()
		limitedStdout := &io.LimitedReader{R: stdout, N: maxOutputSize}
		bufferedReader := bufio.NewReaderSize(limitedStdout, bufferSize)
		if _, err := io.Copy(outBuf, bufferedReader); err != nil {
			copyErr = err
		}
	}()
	go func() {
		defer wg.Done()
		limitedStderr := &io.LimitedReader{R: stderr, N: maxOutputSize}
		bufferedReader := bufio.NewReaderSize(limitedStderr, bufferSize)
		if _, err := io.Copy(errBuf, bufferedReader); err != nil {
			copyErr = err
		}
	}()

	done := make(chan error, 1)
	go func() {
		done <- session.Wait()
	}()

	var sessionErr error
	select {
	case <-ctx.Done():
		_ = session.Signal(ssh.SIGKILL)
		wg.Wait()
		return nil, ctx.Err()
	case sessionErr = <-done:
		wg.Wait()
	}

	if copyErr != nil {
		return nil, &ConnectionError{
			Op:   "output copy",
			Err:  fmt.Errorf("%w: %v", ErrCommandFailed, copyErr),
			Host: s.cfg.Host,
		}
	}

	exitCode := 0
	if sessionErr != nil {
		if exitError, ok := sessionErr.(*ssh.ExitError); ok {
			exitCode = exitError.ExitStatus()
		} else {
			exitCode = 1
		}
	}

	return &Result{
		Stdout:   outBuf.String(),
		Stderr:   errBuf.String(),
		ExitCode: exitCode,
	}, nil
}

func validateRemotePath(p string) bool {
	if p == "" {
		return false
	}
	if !filepath.IsAbs(p) {
		return false
	}
	if strings.Contains(p, "..") {
		return false
	}
	return true
}

func (s *SSHConnection) Upload(ctx context.Context, localPath, remotePath string, mode fs.FileMode) error {
	if err := s.rateLimiter.Wait(ctx); err != nil {
		return err
	}

	return s.circuitBreaker.Call(func() error {
		return s.uploadInternal(ctx, localPath, remotePath, mode)
	})
}

func (s *SSHConnection) uploadInternal(ctx context.Context, localPath, remotePath string, mode fs.FileMode) error {
	localPath = filepath.Clean(localPath)
	if !strings.HasPrefix(localPath, filepath.Clean(".")) && !filepath.IsAbs(localPath) {
		return &ValidationError{
			Field:   "localPath",
			Value:   localPath,
			Message: "path must be absolute or relative to current directory",
		}
	}
	info, err := os.Stat(localPath)
	if err != nil || info.IsDir() {
		return &ConnectionError{
			Op:   "local file access",
			Err:  fmt.Errorf("%w: %v", ErrInvalidPath, err),
			Host: s.cfg.Host,
		}
	}
	if info.Size() > maxTransferSize {
		return &ValidationError{
			Field:   "fileSize",
			Value:   info.Size(),
			Message: fmt.Sprintf("file size %d exceeds maximum %d", info.Size(), maxTransferSize),
		}
	}
	if !validateRemotePath(remotePath) {
		return &ValidationError{
			Field:   "remotePath",
			Value:   remotePath,
			Message: "invalid remote path format",
		}
	}
	session, err := s.client.NewSession()
	if err != nil {
		return errors.New("session error")
	}
	defer session.Close()

	src, err := os.Open(localPath)
	if err != nil {
		return errors.New("open local")
	}
	defer src.Close()

	w, err := session.StdinPipe()
	if err != nil {
		return errors.New("stdin pipe error")
	}

	done := make(chan error, 1)
	go func() {
		defer w.Close()
		defer func() { done <- nil }()

		if _, err := fmt.Fprintf(w, "C%04o %d %s\n", mode.Perm(), info.Size(), filepath.Base(remotePath)); err != nil {
			done <- err
			return
		}
		bufferedSrc := bufio.NewReaderSize(src, bufferSize)
		if _, err := io.Copy(w, bufferedSrc); err != nil {
			done <- err
			return
		}
		if _, err := fmt.Fprint(w, "\x00"); err != nil {
			done <- err
			return
		}
	}()

	var copyErr error
	sessionDone := make(chan error, 1)
	go func() {
		sessionDone <- session.Run(fmt.Sprintf("scp -t %s", quoteArg(remotePath)))
	}()

	select {
	case <-ctx.Done():
		_ = session.Signal(ssh.SIGKILL)
		<-done
		return ctx.Err()
	case copyErr = <-done:
		if copyErr != nil {
			return fmt.Errorf("copy error: %v", copyErr)
		}
	}

	select {
	case <-ctx.Done():
		return ctx.Err()
	case err := <-sessionDone:
		if err != nil {
			return errors.New("scp upload failed")
		}
	}

	return nil
}

func (s *SSHConnection) Download(ctx context.Context, remotePath, localPath string) error {
	if err := s.rateLimiter.Wait(ctx); err != nil {
		return err
	}

	return s.circuitBreaker.Call(func() error {
		return s.downloadInternal(ctx, remotePath, localPath)
	})
}

func (s *SSHConnection) downloadInternal(ctx context.Context, remotePath, localPath string) error {
	if !validateRemotePath(remotePath) {
		return errors.New("invalid remote path")
	}
	localPath = filepath.Clean(localPath)
	if strings.Contains(localPath, "..") {
		return errors.New("invalid local path")
	}
	session, err := s.client.NewSession()
	if err != nil {
		return errors.New("session error")
	}
	defer session.Close()

	stdout, err := session.StdoutPipe()
	if err != nil {
		return errors.New("session stdout")
	}

	outFile, err := os.Create(localPath)
	if err != nil {
		return errors.New("create local")
	}
	defer outFile.Close()

	done := make(chan error, 1)
	go func() {
		done <- session.Run(fmt.Sprintf("scp -f %s", quoteArg(remotePath)))
	}()

	copyDone := make(chan error, 1)
	go func() {
		limitedStdout := &io.LimitedReader{R: stdout, N: maxTransferSize}
		bufferedReader := bufio.NewReaderSize(limitedStdout, bufferSize)
		bufferedWriter := bufio.NewWriterSize(outFile, bufferSize)
		_, err := io.Copy(bufferedWriter, bufferedReader)
		if flushErr := bufferedWriter.Flush(); flushErr != nil && err == nil {
			err = flushErr
		}
		copyDone <- err
	}()

	select {
	case <-ctx.Done():
		_ = session.Signal(ssh.SIGKILL)
		<-copyDone
		return ctx.Err()
	case err := <-done:
		if err != nil {
			return errors.New("scp download failed")
		}
	}

	select {
	case <-ctx.Done():
		return ctx.Err()
	case err := <-copyDone:
		if err != nil {
			return fmt.Errorf("copy error: %v", err)
		}
	}

	return nil
}
