package connection

import (
	"context"
	"crypto/ed25519"
	"errors"
	"strings"
	"testing"
	"time"

	"golang.org/x/crypto/ssh"
)

func TestNewConfig(t *testing.T) {
	cfg := NewConfig("example.com", "testuser")
	if cfg.Host != "example.com" {
		t.Errorf("expected host example.com, got %s", cfg.Host)
	}
	if cfg.User != "testuser" {
		t.Errorf("expected user testuser, got %s", cfg.User)
	}
	if cfg.Port != 22 {
		t.Errorf("expected port 22, got %d", cfg.Port)
	}
	if cfg.Timeout != 30*time.Second {
		t.Errorf("expected timeout 30s, got %v", cfg.Timeout)
	}
}

func TestConfigValidate(t *testing.T) {
	tests := []struct {
		name    string
		cfg     *Config
		wantErr bool
	}{
		{
			name: "valid password auth",
			cfg: func() *Config {
				c := NewConfig("example.com", "testuser")
				c.Password = "secret"
				return c
			}(),
			wantErr: false,
		},
		{
			name:    "empty host",
			cfg:     &Config{Host: "", User: "testuser", Password: "x"},
			wantErr: true,
		},
		{
			name:    "empty user",
			cfg:     &Config{Host: "example.com", User: "", Password: "x"},
			wantErr: true,
		},
		{
			name:    "invalid port",
			cfg:     &Config{Host: "example.com", User: "testuser", Password: "x", Port: -1},
			wantErr: true,
		},
		{
			name:    "missing auth",
			cfg:     &Config{Host: "example.com", User: "testuser"},
			wantErr: true,
		},
		{
			name:    "invalid hostname format",
			cfg:     &Config{Host: "example..com", User: "testuser", Password: "x"},
			wantErr: true,
		},
		{
			name:    "invalid user format",
			cfg:     &Config{Host: "example.com", User: "bad;user", Password: "x"},
			wantErr: true,
		},
		{
			name:    "username too long",
			cfg:     &Config{Host: "example.com", User: strings.Repeat("a", 65), Password: "x"},
			wantErr: true,
		},
		{
			name:    "host with port included",
			cfg:     &Config{Host: "example.com:22", User: "testuser", Password: "x"},
			wantErr: true,
		},
		{
			name: "valid IPv4",
			cfg: func() *Config {
				c := NewConfig("192.168.1.1", "testuser")
				c.Password = "x"
				return c
			}(),
			wantErr: false,
		},
		{
			name: "valid IPv6",
			cfg: func() *Config {
				c := NewConfig("[::1]", "testuser")
				c.Password = "x"
				return c
			}(),
			wantErr: false,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			err := tt.cfg.Validate()
			if (err != nil) != tt.wantErr {
				t.Errorf("Validate() error = %v, wantErr %v", err, tt.wantErr)
			}
		})
	}
}

func TestResultSuccess(t *testing.T) {
	cases := []struct {
		code int
		want bool
	}{
		{0, true},
		{1, false},
		{127, false},
	}
	for _, c := range cases {
		res := &Result{ExitCode: c.code}
		if res.Success() != c.want {
			t.Errorf("ExitCode %d: got %v, want %v", c.code, res.Success(), c.want)
		}
	}
}

func TestConfigStringAndAuthMethod(t *testing.T) {
	cfg := &Config{
		Host:     "example.com",
		Port:     22,
		User:     "tester",
		Password: "supersecret",
		Timeout:  30 * time.Second,
	}
	s := cfg.String()
	if strings.Contains(s, "supersecret") {
		t.Error("String() leaked password")
	}
	if !strings.Contains(s, "Auth:password") {
		t.Error("String() missing password auth indicator")
	}
	if cfg.AuthMethod() != "password" {
		t.Errorf("expected auth method password, got %s", cfg.AuthMethod())
	}

	cfg = &Config{KeyPath: "/tmp/key"}
	if cfg.AuthMethod() != "keyfile" {
		t.Errorf("expected keyfile, got %s", cfg.AuthMethod())
	}
	cfg = &Config{KeyData: []byte("key")}
	if cfg.AuthMethod() != "keydata" {
		t.Errorf("expected keydata, got %s", cfg.AuthMethod())
	}
	cfg = &Config{}
	if cfg.AuthMethod() != "none" {
		t.Errorf("expected none, got %s", cfg.AuthMethod())
	}
}

func TestValidateKeyPathAndParsePrivateKey(t *testing.T) {
	invalid := []byte("-----BEGIN PRIVATE KEY-----\ninvalid\n-----END PRIVATE KEY-----")
	if _, err := parsePrivateKey(invalid); err == nil {
		t.Fatal("expected error for invalid key data")
	}

	_, priv, err := ed25519.GenerateKey(nil)
	if err != nil {
		t.Fatalf("failed to generate ed25519 key: %v", err)
	}
	if _, err := ssh.NewSignerFromKey(priv); err != nil {
		t.Fatalf("failed to create ssh signer: %v", err)
	}
}

func TestCircuitBreaker(t *testing.T) {
	cb := NewCircuitBreaker()

	if cb.State() != StateClosed {
		t.Errorf("expected initial state CLOSED, got %v", cb.State())
	}
	if cb.Failures() != 0 {
		t.Errorf("expected initial failures 0, got %d", cb.Failures())
	}

	err := cb.Call(func() error {
		return nil
	})
	if err != nil {
		t.Errorf("expected no error for successful call, got %v", err)
	}

	for i := 0; i < defaultFailureThreshold; i++ {
		err := cb.Call(func() error {
			return &ConnectionError{Op: "test", Err: errors.New("test error")}
		})
		if err == nil {
			t.Errorf("expected error for failed call %d", i)
		}
	}

	if cb.State() != StateOpen {
		t.Errorf("expected state OPEN after %d failures, got %v", defaultFailureThreshold, cb.State())
	}

	err = cb.Call(func() error {
		return nil
	})
	if err == nil {
		t.Error("expected circuit breaker to reject call when OPEN")
	}
}

func TestCircuitBreakerStates(t *testing.T) {
	states := []CircuitState{StateClosed, StateOpen, StateHalfOpen}
	expected := []string{"CLOSED", "OPEN", "HALF_OPEN"}

	for i, state := range states {
		if state.String() != expected[i] {
			t.Errorf("expected state string %s, got %s", expected[i], state.String())
		}
	}
}

func TestRateLimiter(t *testing.T) {
	rl := NewRateLimiter()
	if rl.Limit() != defaultRateLimit {
		t.Errorf("expected default limit %f, got %f", float64(defaultRateLimit), rl.Limit())
	}
	if rl.Burst() != defaultBurstLimit {
		t.Errorf("expected default burst %d, got %d", defaultBurstLimit, rl.Burst())
	}

	customRPS := 5.0
	customBurst := 10
	customTimeout := 5 * time.Second
	rl2 := NewRateLimiterWithConfig(customRPS, customBurst, customTimeout)

	if rl2.Limit() != customRPS {
		t.Errorf("expected custom limit %f, got %f", customRPS, rl2.Limit())
	}
	if rl2.Burst() != customBurst {
		t.Errorf("expected custom burst %d, got %d", customBurst, rl2.Burst())
	}

	ctx := context.Background()

	start := time.Now()
	err := rl2.Wait(ctx)
	elapsed := time.Since(start)

	if err != nil {
		t.Errorf("expected no error for first request, got %v", err)
	}
	if elapsed > 100*time.Millisecond {
		t.Errorf("first request took too long: %v", elapsed)
	}

	if !rl2.Allow() {
		t.Error("Allow() should return true for available tokens")
	}
}

func TestRateLimiterConfiguration(t *testing.T) {
	rl := NewRateLimiter()

	newLimit := 15.0
	rl.SetLimit(newLimit)
	if rl.Limit() != newLimit {
		t.Errorf("expected limit %f after SetLimit, got %f", newLimit, rl.Limit())
	}

	newBurst := 30
	rl.SetBurst(newBurst)
	if rl.Burst() != newBurst {
		t.Errorf("expected burst %d after SetBurst, got %d", newBurst, rl.Burst())
	}
}

func TestRateLimiterTimeout(t *testing.T) {
	rl := NewRateLimiterWithConfig(0.1, 1, 100*time.Millisecond)

	ctx := context.Background()

	err := rl.Wait(ctx)
	if err != nil {
		t.Errorf("expected no error for first request, got %v", err)
	}

	start := time.Now()
	err = rl.Wait(ctx)
	elapsed := time.Since(start)

	if err == nil {
		t.Error("expected timeout error for second request")
	}

	if elapsed > 200*time.Millisecond {
		t.Errorf("timeout took too long: %v", elapsed)
	}

	if connErr, ok := err.(*ConnectionError); ok {
		if connErr.Op != "rate limiting" {
			t.Errorf("expected rate limiting error, got %s", connErr.Op)
		}
	} else {
		t.Errorf("expected ConnectionError, got %T", err)
	}
}
