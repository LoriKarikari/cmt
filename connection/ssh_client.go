package connection

import (
	"bufio"
	"context"
	"errors"
	"fmt"
	"io"
	"net"
	"regexp"
	"strings"
	"sync"

	"github.com/pkg/sftp"
	"golang.org/x/crypto/ssh"
	"golang.org/x/crypto/ssh/knownhosts"
)

var (
	ErrConnectionFailed = errors.New("connection failed")
	ErrSessionFailed    = errors.New("session creation failed")
	ErrCommandFailed    = errors.New("command execution failed")
	ErrUnsafeCommand    = errors.New("unsafe command")
)

const (
	maxOutputSize = 10 * 1024 * 1024
	bufferSize    = 64 * 1024
)

var safeCommandRegex = regexp.MustCompile(`^[a-zA-Z0-9\-._/ ]+$`)

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