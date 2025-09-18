package connection

import (
	"context"
	"errors"
	"fmt"
	"io/fs"
	"net"
	"os"
	"path/filepath"
	"regexp"
	"strings"
	"sync"
	"time"
)

var (
	hostnameRegex *regexp.Regexp
	usernameRegex *regexp.Regexp
	regexOnce     sync.Once
)

func initRegexes() {
	hostnameRegex = regexp.MustCompile(`^[a-zA-Z0-9]([a-zA-Z0-9\-]{0,61}[a-zA-Z0-9])?(\.[a-zA-Z0-9]([a-zA-Z0-9\-]{0,61}[a-zA-Z0-9])?)*$`)
	usernameRegex = regexp.MustCompile(`^[a-zA-Z_][a-zA-Z0-9_-]*$`)
}

type Connection interface {
	Execute(ctx context.Context, command string) (*Result, error)
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
	Host     string
	Port     int
	User     string
	Password string
	KeyPath  string
	KeyData  []byte
	Timeout  time.Duration
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

func NewConfig(host, user string) *Config {
	return &Config{
		Host:    host,
		Port:    22,
		User:    user,
		Timeout: 30 * time.Second,
	}
}

func (c *Config) Validate() error {
	if err := c.validateHost(); err != nil {
		return fmt.Errorf("host validation failed: %w", err)
	}

	if err := c.validateAddress(); err != nil {
		return fmt.Errorf("address validation failed: %w", err)
	}

	if err := c.validateUser(); err != nil {
		return fmt.Errorf("user validation failed: %w", err)
	}

	if err := c.validateTimeout(); err != nil {
		return fmt.Errorf("timeout validation failed: %w", err)
	}

	if err := c.validateAuthentication(); err != nil {
		return fmt.Errorf("authentication validation failed: %w", err)
	}

	if err := c.validateKeyPath(); err != nil {
		return fmt.Errorf("key path validation failed: %w", err)
	}

	return nil
}

func (c *Config) validateHost() error {
	regexOnce.Do(initRegexes)

	if c.Host == "" {
		return errors.New("host cannot be empty")
	}

	host := strings.TrimSpace(c.Host)

	if strings.Contains(host, ":") && !strings.HasPrefix(host, "[") {
		return fmt.Errorf("host '%s' contains port, use Port field instead", host)
	}

	if ip := net.ParseIP(host); ip != nil {
		return nil
	}

	if strings.HasPrefix(host, "[") && strings.HasSuffix(host, "]") {
		ipv6 := host[1 : len(host)-1]
		if ip := net.ParseIP(ipv6); ip != nil && ip.To4() == nil {
			return nil
		}
		return fmt.Errorf("invalid IPv6 address format: '%s'", host)
	}

	if !hostnameRegex.MatchString(host) {
		return fmt.Errorf("invalid hostname format: '%s' contains invalid characters or structure", host)
	}

	if len(host) > 253 {
		return fmt.Errorf("hostname '%s' too long (%d characters, max 253)", host, len(host))
	}

	return nil
}

func (c *Config) validateAddress() error {
	if c.Port < 1 || c.Port > 65535 {
		return fmt.Errorf("port %d is invalid, must be between 1 and 65535", c.Port)
	}

	host := c.Host
	if strings.HasPrefix(host, "[") && strings.HasSuffix(host, "]") {
		host = host[1 : len(host)-1]
	}

	addr := net.JoinHostPort(host, fmt.Sprintf("%d", c.Port))
	_, _, err := net.SplitHostPort(addr)
	if err != nil {
		return fmt.Errorf("invalid host:port combination '%s:%d': %w", c.Host, c.Port, err)
	}
	return nil
}

func (c *Config) validateUser() error {
	regexOnce.Do(initRegexes)

	if c.User == "" {
		return errors.New("user cannot be empty")
	}

	user := strings.TrimSpace(c.User)
	if !usernameRegex.MatchString(user) {
		return fmt.Errorf("invalid username format: '%s' must start with letter or underscore, contain only letters, numbers, underscores, and hyphens", user)
	}

	if len(user) > 32 {
		return fmt.Errorf("username '%s' too long (%d characters, max 32)", user, len(user))
	}

	return nil
}

func (c *Config) validateTimeout() error {
	if c.Timeout <= 0 {
		return fmt.Errorf("timeout %v must be positive", c.Timeout)
	}

	if c.Timeout > 10*time.Minute {
		return fmt.Errorf("timeout %v too large (max 10 minutes)", c.Timeout)
	}

	return nil
}

func (c *Config) validateAuthentication() error {
	hasPassword := c.Password != ""
	hasKeyPath := c.KeyPath != ""
	hasKeyData := len(c.KeyData) > 0

	authMethodCount := 0
	if hasPassword {
		authMethodCount++
	}
	if hasKeyPath {
		authMethodCount++
	}
	if hasKeyData {
		authMethodCount++
	}

	if authMethodCount == 0 {
		return errors.New("authentication required: provide password, key path, or key data")
	}

	if authMethodCount > 1 {
		return errors.New("multiple authentication methods provided: use only one of password, key path, or key data")
	}

	if hasKeyData {
		if err := c.validateKeyData(); err != nil {
			return fmt.Errorf("key data validation failed: %w", err)
		}
	}

	return nil
}

func (c *Config) validateKeyData() error {
	if len(c.KeyData) == 0 {
		return nil
	}

	keyStr := string(c.KeyData)
	if !strings.Contains(keyStr, "BEGIN") || !strings.Contains(keyStr, "PRIVATE KEY") {
		return errors.New("key data does not appear to be a valid private key format")
	}

	if len(c.KeyData) < 200 {
		return fmt.Errorf("key data too short (%d bytes), may be invalid", len(c.KeyData))
	}

	return nil
}

func (c *Config) validateKeyPath() error {
	if c.KeyPath == "" {
		return nil
	}

	keyPath := c.KeyPath
	if strings.HasPrefix(keyPath, "~/") {
		homeDir, err := os.UserHomeDir()
		if err != nil {
			return fmt.Errorf("failed to get home directory: %w", err)
		}
		keyPath = filepath.Join(homeDir, keyPath[2:])
	}

	c.KeyPath = filepath.Clean(keyPath)

	if _, err := os.Stat(c.KeyPath); err != nil {
		return fmt.Errorf("key file not accessible: %w", err)
	}

	return nil
}