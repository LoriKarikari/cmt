package connection

import (
	"context"
	"errors"
	"io/fs"
	"testing"
	"time"
)

func TestNewRetryConfig(t *testing.T) {
	cfg := NewRetryConfig()
	if cfg.MaxAttempts != 3 {
		t.Errorf("expected MaxAttempts 3, got %d", cfg.MaxAttempts)
	}
	if cfg.InitialDelay != 100*time.Millisecond {
		t.Errorf("expected InitialDelay 100ms, got %v", cfg.InitialDelay)
	}
	if cfg.MaxDelay != 30*time.Second {
		t.Errorf("expected MaxDelay 30s, got %v", cfg.MaxDelay)
	}
	if cfg.Multiplier != 2.0 {
		t.Errorf("expected Multiplier 2.0, got %f", cfg.Multiplier)
	}
	if !cfg.Jitter {
		t.Error("expected Jitter true, got false")
	}
}

func TestRetryConfigIsRetryable(t *testing.T) {
	cfg := NewRetryConfig()

	if cfg.IsRetryable(nil) {
		t.Error("nil error should not be retryable")
	}

	connErr := &ConnectionError{Op: "test", Err: errors.New("test")}
	if !cfg.IsRetryable(connErr) {
		t.Error("ConnectionError should be retryable")
	}

	regularErr := errors.New("regular error")
	if cfg.IsRetryable(regularErr) {
		t.Error("regular error should not be retryable")
	}
}

func TestRetryConfigCalculateDelay(t *testing.T) {
	cfg := &RetryConfig{
		InitialDelay: 100 * time.Millisecond,
		MaxDelay:     1 * time.Second,
		Multiplier:   2.0,
		Jitter:       false,
	}

	delay0 := cfg.CalculateDelay(0)
	if delay0 != 0 {
		t.Errorf("expected delay 0 for attempt 0, got %v", delay0)
	}

	delay1 := cfg.CalculateDelay(1)
	if delay1 != 100*time.Millisecond {
		t.Errorf("expected delay 100ms for attempt 1, got %v", delay1)
	}

	delay2 := cfg.CalculateDelay(2)
	if delay2 != 200*time.Millisecond {
		t.Errorf("expected delay 200ms for attempt 2, got %v", delay2)
	}

	delay10 := cfg.CalculateDelay(10)
	if delay10 != 1*time.Second {
		t.Errorf("expected delay capped at 1s for attempt 10, got %v", delay10)
	}
}

func TestRetryConfigCalculateDelayWithJitter(t *testing.T) {
	cfg := &RetryConfig{
		InitialDelay: 100 * time.Millisecond,
		MaxDelay:     1 * time.Second,
		Multiplier:   2.0,
		Jitter:       true,
	}

	delays := make([]time.Duration, 10)
	for i := 0; i < 10; i++ {
		delays[i] = cfg.CalculateDelay(1)
	}

	allSame := true
	for i := 1; i < len(delays); i++ {
		if delays[i] != delays[0] {
			allSame = false
			break
		}
	}

	if allSame {
		t.Error("with jitter enabled, delays should vary")
	}

	for _, delay := range delays {
		if delay < 0 {
			t.Errorf("delay should not be negative, got %v", delay)
		}
	}
}

func TestWithRetrySuccess(t *testing.T) {
	cfg := NewRetryConfig()
	cfg.MaxAttempts = 3

	attempts := 0
	err := WithRetry(context.Background(), cfg, func() error {
		attempts++
		return nil
	})

	if err != nil {
		t.Errorf("expected no error, got %v", err)
	}
	if attempts != 1 {
		t.Errorf("expected 1 attempt, got %d", attempts)
	}
}

func TestWithRetryEventualSuccess(t *testing.T) {
	cfg := NewRetryConfig()
	cfg.MaxAttempts = 3
	cfg.InitialDelay = 1 * time.Millisecond
	cfg.Jitter = false

	attempts := 0
	err := WithRetry(context.Background(), cfg, func() error {
		attempts++
		if attempts < 3 {
			return &ConnectionError{Op: "test", Err: errors.New("temporary failure")}
		}
		return nil
	})

	if err != nil {
		t.Errorf("expected no error, got %v", err)
	}
	if attempts != 3 {
		t.Errorf("expected 3 attempts, got %d", attempts)
	}
}

func TestWithRetryMaxAttemptsExceeded(t *testing.T) {
	cfg := NewRetryConfig()
	cfg.MaxAttempts = 2
	cfg.InitialDelay = 1 * time.Millisecond
	cfg.Jitter = false

	attempts := 0
	err := WithRetry(context.Background(), cfg, func() error {
		attempts++
		return &ConnectionError{Op: "test", Err: errors.New("persistent failure")}
	})

	if err == nil {
		t.Error("expected error after max attempts")
	}
	if attempts != 2 {
		t.Errorf("expected 2 attempts, got %d", attempts)
	}
}

func TestWithRetryNonRetryableError(t *testing.T) {
	cfg := NewRetryConfig()
	cfg.MaxAttempts = 3

	attempts := 0
	nonRetryableErr := errors.New("non-retryable error")
	err := WithRetry(context.Background(), cfg, func() error {
		attempts++
		return nonRetryableErr
	})

	if err != nonRetryableErr {
		t.Errorf("expected non-retryable error to be returned, got %v", err)
	}
	if attempts != 1 {
		t.Errorf("expected 1 attempt for non-retryable error, got %d", attempts)
	}
}

func TestWithRetryContextCancellation(t *testing.T) {
	cfg := NewRetryConfig()
	cfg.MaxAttempts = 5
	cfg.InitialDelay = 100 * time.Millisecond

	ctx, cancel := context.WithTimeout(context.Background(), 50*time.Millisecond)
	defer cancel()

	attempts := 0
	err := WithRetry(ctx, cfg, func() error {
		attempts++
		return &ConnectionError{Op: "test", Err: errors.New("failure")}
	})

	if err == nil {
		t.Error("expected context cancellation error")
	}
	if attempts > 2 {
		t.Errorf("expected few attempts due to context cancellation, got %d", attempts)
	}
}

func TestWithRetryResult(t *testing.T) {
	cfg := NewRetryConfig()
	cfg.MaxAttempts = 3
	cfg.InitialDelay = 1 * time.Millisecond
	cfg.Jitter = false

	attempts := 0
	result, err := WithRetryResult(context.Background(), cfg, func() (string, error) {
		attempts++
		if attempts < 2 {
			return "", &ConnectionError{Op: "test", Err: errors.New("failure")}
		}
		return "success", nil
	})

	if err != nil {
		t.Errorf("expected no error, got %v", err)
	}
	if result != "success" {
		t.Errorf("expected 'success', got '%s'", result)
	}
	if attempts != 2 {
		t.Errorf("expected 2 attempts, got %d", attempts)
	}
}

func TestRetryableSSHConnection(t *testing.T) {
	mockConn := &mockConnection{}
	retryConfig := NewRetryConfig()
	retryConfig.MaxAttempts = 1

	retryableConn := NewRetryableSSHConnection(mockConn, retryConfig)

	ctx := context.Background()

	_, err := retryableConn.Execute(ctx, "test command")
	if err == nil {
		t.Error("expected error from mock connection")
	}

	_, err = retryableConn.ExecuteArgs(ctx, "test", "arg1")
	if err == nil {
		t.Error("expected error from mock connection")
	}

	err = retryableConn.Upload(ctx, "local", "remote", 0644)
	if err == nil {
		t.Error("expected error from mock connection")
	}

	err = retryableConn.Download(ctx, "remote", "local")
	if err == nil {
		t.Error("expected error from mock connection")
	}

	err = retryableConn.Close()
	if err == nil {
		t.Error("expected error from mock connection")
	}
}

type mockConnection struct{}

func (m *mockConnection) Execute(ctx context.Context, command string) (*Result, error) {
	return nil, &ConnectionError{Op: "execute", Err: errors.New("mock error")}
}

func (m *mockConnection) ExecuteArgs(ctx context.Context, cmd string, args ...string) (*Result, error) {
	return nil, &ConnectionError{Op: "execute", Err: errors.New("mock error")}
}

func (m *mockConnection) Upload(ctx context.Context, localPath, remotePath string, mode fs.FileMode) error {
	return &ConnectionError{Op: "upload", Err: errors.New("mock error")}
}

func (m *mockConnection) Download(ctx context.Context, remotePath, localPath string) error {
	return &ConnectionError{Op: "download", Err: errors.New("mock error")}
}

func (m *mockConnection) Close() error {
	return &ConnectionError{Op: "close", Err: errors.New("mock error")}
}