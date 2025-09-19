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
	"github.com/pkg/sftp"
	"golang.org/x/crypto/ssh"
	"golang.org/x/crypto/ssh/knownhosts"
	"golang.org/x/time/rate"
)

type ConnectionError struct {
	Op   string
	Err  error
	Host string
}

func (e *ConnectionError) Error() string {
	if e.Host != "" {
		return fmt.Sprintf("connection error [%s@%s]: %v", e.Op, e.Host, e.Err)
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
	cachedSigner         ssh.Signer    `validate:"-"`
}

const (
	maxOutputSize         = 10 * 1024 * 1024
	maxKeyFileSize        = 32 * 1024
	bufferSize            = 64 * 1024
	maxTransferSize       = 100 * 1024 * 1024
	defaultFailureThreshold = 5
	defaultTimeout          = 60 * time.Second
	defaultRateLimit        = 10.0
	defaultBurstLimit       = 20
	defaultRequestTimeout   = 30 * time.Second
)

var (
	validate      *validator.Validate
	validatorOnce sync.Once
	safeCommandRegex = regexp.MustCompile(`^[a-zA-Z0-9\-._/ ]+$`)
)

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
	if c.cachedSigner != nil {
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
}

func (c *Config) Validate() error {
	validatorOnce.Do(initValidator)
	return validate.Struct(c)
}

func validateUsernameTag(fl validator.FieldLevel) bool {
	username := fl.Field().String()
	if len(username) == 0 || len(username) > 32 {
		return false
	}
	for i, r := range username {
		if i == 0 {
			if !((r >= 'a' && r <= 'z') || (r >= 'A' && r <= 'Z') || r == '_') {
				return false
			}
		} else {
			if !((r >= 'a' && r <= 'z') || (r >= 'A' && r <= 'Z') || (r >= '0' && r <= '9') || r == '_' || r == '-') {
				return false
			}
		}
	}
	return true
}

func validateHostTag(fl validator.FieldLevel) bool {
	host := strings.TrimSpace(fl.Field().String())
	if host == "" {
		return false
	}
	if strings.Contains(host, ":") && !strings.HasPrefix(host, "[") {
		return false
	}
	if ip := net.ParseIP(host); ip != nil {
		return true
	}
	if strings.HasPrefix(host, "[") && strings.HasSuffix(host, "]") {
		ipv6 := host[1 : len(host)-1]
		return net.ParseIP(ipv6) != nil
	}
	return len(host) <= 253 && !strings.Contains(host, " ")
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
	if strings.Contains(cfg.KeyPath, "..") {
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

type CircuitBreaker struct {
	mu               sync.RWMutex
	failureThreshold int
	resetTimeout     time.Duration
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
				Op:   "circuit breaker",
				Err:  errors.New("circuit breaker is OPEN"),
				Host: "",
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
				Op:   "rate limiting",
				Err:  errors.New("rate limit timeout exceeded"),
				Host: "",
			}
		}
		return &ConnectionError{
			Op:   "rate limiting",
			Err:  fmt.Errorf("rate limit error: %v", err),
			Host: "",
		}
	}
	return nil
}

func (rl *RateLimiter) Allow() bool {
	return rl.limiter.Allow()
}

func (rl *RateLimiter) Limiter() *rate.Limiter {
	return rl.limiter
}

type SSHConnection struct {
	client         *ssh.Client
	sftpClient     *sftp.Client
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
	var sftpClient *sftp.Client
	if sftpC, err := sftp.NewClient(client); err == nil {
		sftpClient = sftpC
	}
	return &SSHConnection{
		client:         client,
		sftpClient:     sftpClient,
		cfg:            cfg,
		circuitBreaker: NewCircuitBreaker(),
		rateLimiter:    NewRateLimiter(),
	}, nil
}

func (s *SSHConnection) Close() error {
	if s.sftpClient != nil {
		_ = s.sftpClient.Close()
	}
	err := s.client.Close()
	if s.cfg != nil {
		s.cfg.ClearSensitiveData()
	}
	return err
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
			copyErr = fmt.Errorf("stdout copy error: %v", err)
		}
	}()
	go func() {
		defer wg.Done()
		limitedStderr := &io.LimitedReader{R: stderr, N: maxOutputSize}
		bufferedReader := bufio.NewReaderSize(limitedStderr, bufferSize)
		if _, err := io.Copy(errBuf, bufferedReader); err != nil {
			copyErr = fmt.Errorf("stderr copy error: %v", err)
		}
	}()
	done := make(chan error, 1)
	go func() { done <- session.Wait() }()
	select {
	case <-ctx.Done():
		session.Signal(ssh.SIGKILL)
		return nil, &ConnectionError{
			Op:   "command execution",
			Err:  fmt.Errorf("%w: command timed out: %v", ErrCommandFailed, ctx.Err()),
			Host: s.cfg.Host,
		}
	case err := <-done:
		wg.Wait()
		if copyErr != nil {
			return nil, &ConnectionError{
				Op:   "output copy",
				Err:  fmt.Errorf("%w: %v", ErrCommandFailed, copyErr),
				Host: s.cfg.Host,
			}
		}
		exitCode := 0
		if err != nil {
			if exitErr, ok := err.(*ssh.ExitError); ok {
				exitCode = exitErr.ExitStatus()
			} else {
				return nil, &ConnectionError{
					Op:   "command execution",
					Err:  fmt.Errorf("%w: %v", ErrCommandFailed, err),
					Host: s.cfg.Host,
				}
			}
		}
		return &Result{
			Stdout:   outBuf.String(),
			Stderr:   errBuf.String(),
			ExitCode: exitCode,
		}, nil
	}
}

func (s *SSHConnection) Upload(ctx context.Context, localPath, remotePath string, mode fs.FileMode) error {
	if err := s.rateLimiter.Wait(ctx); err != nil {
		return err
	}
	return s.circuitBreaker.Call(func() error {
		if s.sftpClient != nil {
			return s.uploadSFTP(localPath, remotePath, mode)
		}
		return s.uploadInternal(ctx, localPath, remotePath, mode)
	})
}

func (s *SSHConnection) Download(ctx context.Context, remotePath, localPath string) error {
	if err := s.rateLimiter.Wait(ctx); err != nil {
		return err
	}
	return s.circuitBreaker.Call(func() error {
		if s.sftpClient != nil {
			return s.downloadSFTP(remotePath, localPath)
		}
		return s.downloadInternal(ctx, remotePath, localPath)
	})
}

func (s *SSHConnection) uploadSFTP(localPath, remotePath string, mode fs.FileMode) error {
	src, err := os.Open(localPath)
	if err != nil {
		return fmt.Errorf("open local file: %w", err)
	}
	defer src.Close()
	dst, err := s.sftpClient.Create(remotePath)
	if err != nil {
		return fmt.Errorf("create remote file: %w", err)
	}
	defer dst.Close()
	if _, err := io.Copy(dst, src); err != nil {
		return fmt.Errorf("copy to remote: %w", err)
	}
	return s.sftpClient.Chmod(remotePath, mode)
}

func (s *SSHConnection) downloadSFTP(remotePath, localPath string) error {
	src, err := s.sftpClient.Open(remotePath)
	if err != nil {
		return fmt.Errorf("open remote file: %w", err)
	}
	defer src.Close()
	dst, err := os.Create(localPath)
	if err != nil {
		return fmt.Errorf("create local file: %w", err)
	}
	defer dst.Close()
	_, err = io.Copy(dst, src)
	return err
}

func (s *SSHConnection) uploadInternal(ctx context.Context, localPath, remotePath string, mode fs.FileMode) error {
	info, err := os.Stat(localPath)
	if err != nil {
		return fmt.Errorf("%w: cannot stat local file: %v", ErrInvalidPath, err)
	}
	if info.Size() > maxTransferSize {
		return fmt.Errorf("%w: file too large (%d > %d bytes)",
			ErrTransferFailed, info.Size(), maxTransferSize)
	}
	if strings.Contains(remotePath, "..") || strings.Contains(remotePath, "~") {
		return fmt.Errorf("%w: invalid remote path", ErrInvalidPath)
	}
	session, err := s.client.NewSession()
	if err != nil {
		return fmt.Errorf("%w: failed to create session: %v", ErrSessionFailed, err)
	}
	defer session.Close()
	stdin, err := session.StdinPipe()
	if err != nil {
		return fmt.Errorf("%w: failed to create stdin pipe: %v", ErrTransferFailed, err)
	}
	defer stdin.Close()
	targetDir := filepath.Dir(remotePath)
	baseName := filepath.Base(remotePath)
	go func() {
		defer stdin.Close()
		fmt.Fprintf(stdin, "C%#o %d %s\n", mode.Perm(), info.Size(), baseName)
		file, err := os.Open(localPath)
		if err != nil {
			return
		}
		defer file.Close()
		if _, err := io.Copy(stdin, file); err != nil {
			return
		}
		fmt.Fprint(stdin, "\x00")
	}()
	cmd := fmt.Sprintf("scp -t %s", quoteArg(targetDir))
	if err := session.Run(cmd); err != nil {
		return fmt.Errorf("%w: scp command failed: %v", ErrTransferFailed, err)
	}
	return nil
}

func (s *SSHConnection) downloadInternal(ctx context.Context, remotePath, localPath string) error {
	if strings.Contains(remotePath, "..") || strings.Contains(remotePath, "~") {
		return fmt.Errorf("%w: invalid remote path", ErrInvalidPath)
	}
	session, err := s.client.NewSession()
	if err != nil {
		return fmt.Errorf("%w: failed to create session: %v", ErrSessionFailed, err)
	}
	defer session.Close()
	stdout, err := session.StdoutPipe()
	if err != nil {
		return fmt.Errorf("%w: failed to create stdout pipe: %v", ErrTransferFailed, err)
	}
	targetDir := filepath.Dir(remotePath)
	baseName := filepath.Base(remotePath)
	cmd := fmt.Sprintf("scp -f %s", quoteArg(remotePath))
	localFile, err := os.Create(localPath)
	if err != nil {
		return fmt.Errorf("%w: failed to create local file: %v", ErrTransferFailed, err)
	}
	defer localFile.Close()
	stdin, err := session.StdinPipe()
	if err != nil {
		return fmt.Errorf("%w: failed to create stdin pipe: %v", ErrTransferFailed, err)
	}
	go func() {
		defer stdin.Close()
		fmt.Fprint(stdin, "\x00")
	}()
	if err := session.Start(cmd); err != nil {
		return fmt.Errorf("%w: failed to start scp: %v", ErrTransferFailed, err)
	}
	buf := make([]byte, bufferSize)
	for {
		n, err := stdout.Read(buf)
		if n > 0 {
			if _, werr := localFile.Write(buf[:n]); werr != nil {
				return fmt.Errorf("%w: write error: %v", ErrTransferFailed, werr)
			}
		}
		if err == io.EOF {
			break
		}
		if err != nil {
			return fmt.Errorf("%w: read error: %v", ErrTransferFailed, err)
		}
	}
	if err := session.Wait(); err != nil {
		return fmt.Errorf("%w: scp wait error: %v", ErrTransferFailed, err)
	}
	return nil
}
