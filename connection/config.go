package connection

import (
	"crypto/x509"
	"encoding/pem"
	"errors"
	"fmt"
	"net"
	"os"
	"strings"
	"sync"
	"time"

	"github.com/go-playground/validator/v10"
	"golang.org/x/crypto/ssh"
)

type ValidationError struct {
	Field   string
	Value   interface{}
	Message string
}

func (e *ValidationError) Error() string {
	return fmt.Sprintf("validation error: %s: %s", e.Field, e.Message)
}

var (
	ErrInvalidConfig = errors.New("invalid configuration")
	ErrInvalidKey    = errors.New("invalid key")
)

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
	maxKeyFileSize = 32 * 1024
)

var (
	validate      *validator.Validate
	validatorOnce sync.Once
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