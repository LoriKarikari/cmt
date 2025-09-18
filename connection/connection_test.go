package connection

import (
	"strings"
	"testing"
	"time"
)

func TestNewConfig(t *testing.T) {
	config := NewConfig("example.com", "testuser")

	if config.Host != "example.com" {
		t.Errorf("expected host 'example.com', got '%s'", config.Host)
	}
	if config.User != "testuser" {
		t.Errorf("expected user 'testuser', got '%s'", config.User)
	}
	if config.Port != 22 {
		t.Errorf("expected port 22, got %d", config.Port)
	}
	if config.Timeout != 30*time.Second {
		t.Errorf("expected timeout 30s, got %v", config.Timeout)
	}
}

func TestConfigValidate(t *testing.T) {
	tests := []struct {
		name    string
		config  *Config
		wantErr bool
	}{
		{
			name: "valid config with NewConfig defaults",
			config: func() *Config {
				c := NewConfig("example.com", "testuser")
				c.Password = "test"
				return c
			}(),
			wantErr: false,
		},
		{
			name: "empty host",
			config: &Config{
				Host: "",
				Port: 22,
				User: "testuser",
			},
			wantErr: true,
		},
		{
			name: "empty user",
			config: &Config{
				Host: "example.com",
				Port: 22,
				User: "",
			},
			wantErr: true,
		},
		{
			name: "invalid port negative",
			config: &Config{
				Host: "example.com",
				Port: -1,
				User: "testuser",
			},
			wantErr: true,
		},
		{
			name: "invalid port too high",
			config: &Config{
				Host: "example.com",
				Port: 65536,
				User: "testuser",
			},
			wantErr: true,
		},
		{
			name: "missing authentication",
			config: &Config{
				Host:    "example.com",
				Port:    22,
				User:    "testuser",
				Timeout: 30 * time.Second,
			},
			wantErr: true,
		},
		{
			name: "invalid host with command injection chars",
			config: &Config{
				Host:     "example.com; rm -rf /",
				Port:     22,
				User:     "testuser",
				Password: "test",
				Timeout:  30 * time.Second,
			},
			wantErr: true,
		},
		{
			name: "invalid user with command injection chars",
			config: &Config{
				Host:     "example.com",
				Port:     22,
				User:     "test;user",
				Password: "test",
				Timeout:  30 * time.Second,
			},
			wantErr: true,
		},
		{
			name: "invalid hostname format",
			config: &Config{
				Host:     "example..com",
				Port:     22,
				User:     "testuser",
				Password: "test",
				Timeout:  30 * time.Second,
			},
			wantErr: true,
		},
		{
			name: "zero timeout",
			config: &Config{
				Host:     "example.com",
				Port:     22,
				User:     "testuser",
				Password: "test",
				Timeout:  0,
			},
			wantErr: true,
		},
		{
			name: "valid config with password",
			config: &Config{
				Host:     "example.com",
				Port:     22,
				User:     "testuser",
				Password: "test",
				Timeout:  30 * time.Second,
			},
			wantErr: false,
		},
		{
			name: "valid config with IP address",
			config: &Config{
				Host:     "192.168.1.1",
				Port:     22,
				User:     "testuser",
				Password: "test",
				Timeout:  30 * time.Second,
			},
			wantErr: false,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			err := tt.config.Validate()
			if (err != nil) != tt.wantErr {
				t.Errorf("Config.Validate() error = %v, wantErr %v", err, tt.wantErr)
			}
		})
	}
}

func TestResultSuccess(t *testing.T) {
	tests := []struct {
		name     string
		result   *Result
		expected bool
	}{
		{
			name: "success exit code 0",
			result: &Result{
				ExitCode: 0,
			},
			expected: true,
		},
		{
			name: "failure exit code 1",
			result: &Result{
				ExitCode: 1,
			},
			expected: false,
		},
		{
			name: "failure exit code 127",
			result: &Result{
				ExitCode: 127,
			},
			expected: false,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if got := tt.result.Success(); got != tt.expected {
				t.Errorf("Result.Success() = %v, want %v", got, tt.expected)
			}
		})
	}
}

func TestConfigString(t *testing.T) {
	config := &Config{
		Host:     "example.com",
		Port:     22,
		User:     "testuser",
		Password: "secretpassword",
		Timeout:  30 * time.Second,
	}

	str := config.String()
	if strings.Contains(str, "secretpassword") {
		t.Error("Config.String() leaked password in output")
	}
	if !strings.Contains(str, "Auth:password") {
		t.Error("Config.String() should indicate password auth type")
	}
	if !strings.Contains(str, "example.com") {
		t.Error("Config.String() should contain host")
	}
}