package connection

import (
	"context"
	"errors"
	"fmt"
	"io/fs"
	"net"
	"net/url"
	"os"
	"path/filepath"
	"regexp"
	"time"
)

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

func (c *Config) String() string {
	authType := "none"
	if c.Password != "" {
		authType = "password"
	} else if c.KeyPath != "" {
		authType = "keyfile"
	} else if len(c.KeyData) > 0 {
		authType = "keydata"
	}
	return fmt.Sprintf("Config{Host:%s, Port:%d, User:%s, Auth:%s, Timeout:%v}",
		c.Host, c.Port, c.User, authType, c.Timeout)
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
	if c.Host == "" {
		return errors.New("host cannot be empty")
	}

	if ip := net.ParseIP(c.Host); ip != nil {
		return nil
	}

	u, err := url.Parse("ssh://" + c.Host)
	if err != nil {
		return fmt.Errorf("invalid host format: %w", err)
	}

	hostnameRegex := regexp.MustCompile(`^[a-zA-Z0-9]([a-zA-Z0-9\-]{0,61}[a-zA-Z0-9])?(\.[a-zA-Z0-9]([a-zA-Z0-9\-]{0,61}[a-zA-Z0-9])?)*$`)
	if !hostnameRegex.MatchString(u.Hostname()) {
		return errors.New("invalid hostname format")
	}

	return nil
}

func (c *Config) validateAddress() error {
	addr := net.JoinHostPort(c.Host, fmt.Sprintf("%d", c.Port))
	_, _, err := net.SplitHostPort(addr)
	if err != nil {
		return fmt.Errorf("invalid host:port combination: %w", err)
	}
	return nil
}

func (c *Config) validateUser() error {
	if c.User == "" {
		return errors.New("user cannot be empty")
	}

	usernameRegex := regexp.MustCompile(`^[a-zA-Z_][a-zA-Z0-9_-]*$`)
	if !usernameRegex.MatchString(c.User) {
		return errors.New("invalid username format")
	}

	return nil
}

func (c *Config) validateTimeout() error {
	if c.Timeout <= 0 {
		return errors.New("timeout must be positive")
	}

	if c.Timeout > 10*time.Minute {
		return errors.New("timeout too large (max 10 minutes)")
	}

	return nil
}

func (c *Config) validateAuthentication() error {
	hasPassword := c.Password != ""
	hasKeyPath := c.KeyPath != ""
	hasKeyData := len(c.KeyData) > 0

	if !hasPassword && !hasKeyPath && !hasKeyData {
		return errors.New("authentication required: provide password, key path, or key data")
	}

	return nil
}

func (c *Config) validateKeyPath() error {
	if c.KeyPath == "" {
		return nil
	}

	c.KeyPath = filepath.Clean(c.KeyPath)

	if _, err := os.Stat(c.KeyPath); err != nil {
		return fmt.Errorf("key file not accessible: %w", err)
	}

	return nil
}