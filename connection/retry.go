package connection

import (
	"context"
	"fmt"
	"io/fs"
	"math"
	"math/rand"
	"time"
)

type RetryConfig struct {
	MaxAttempts   int
	InitialDelay  time.Duration
	MaxDelay      time.Duration
	Multiplier    float64
	Jitter        bool
	RetryableFunc func(error) bool
}

func NewRetryConfig() *RetryConfig {
	return &RetryConfig{
		MaxAttempts:  3,
		InitialDelay: 100 * time.Millisecond,
		MaxDelay:     30 * time.Second,
		Multiplier:   2.0,
		Jitter:       true,
		RetryableFunc: func(err error) bool {
			if err == nil {
				return false
			}
			switch err.(type) {
			case *ConnectionError:
				return true
			default:
				return false
			}
		},
	}
}

func (rc *RetryConfig) IsRetryable(err error) bool {
	if rc.RetryableFunc != nil {
		return rc.RetryableFunc(err)
	}
	return false
}

func (rc *RetryConfig) CalculateDelay(attempt int) time.Duration {
	if attempt <= 0 {
		return 0
	}

	delay := float64(rc.InitialDelay) * math.Pow(rc.Multiplier, float64(attempt-1))

	if delay > float64(rc.MaxDelay) {
		delay = float64(rc.MaxDelay)
	}

	if rc.Jitter {
		jitter := delay * 0.1 * (rand.Float64()*2 - 1)
		delay += jitter
		if delay < 0 {
			delay = float64(rc.InitialDelay)
		}
	}

	return time.Duration(delay)
}

type RetryableOperation func() error

func WithRetry(ctx context.Context, config *RetryConfig, operation RetryableOperation) error {
	if config == nil {
		config = NewRetryConfig()
	}

	var lastErr error
	for attempt := 1; attempt <= config.MaxAttempts; attempt++ {
		select {
		case <-ctx.Done():
			return fmt.Errorf("operation cancelled: %w", ctx.Err())
		default:
		}

		lastErr = operation()
		if lastErr == nil {
			return nil
		}

		if attempt == config.MaxAttempts {
			break
		}

		if !config.IsRetryable(lastErr) {
			return lastErr
		}

		delay := config.CalculateDelay(attempt)
		if delay > 0 {
			select {
			case <-ctx.Done():
				return fmt.Errorf("operation cancelled during retry delay: %w", ctx.Err())
			case <-time.After(delay):
			}
		}
	}

	return fmt.Errorf("operation failed after %d attempts: %w", config.MaxAttempts, lastErr)
}

type RetryableResult[T any] func() (T, error)

func WithRetryResult[T any](ctx context.Context, config *RetryConfig, operation RetryableResult[T]) (T, error) {
	if config == nil {
		config = NewRetryConfig()
	}

	var zero T
	var lastErr error
	var result T

	for attempt := 1; attempt <= config.MaxAttempts; attempt++ {
		select {
		case <-ctx.Done():
			return zero, fmt.Errorf("operation cancelled: %w", ctx.Err())
		default:
		}

		result, lastErr = operation()
		if lastErr == nil {
			return result, nil
		}

		if attempt == config.MaxAttempts {
			break
		}

		if !config.IsRetryable(lastErr) {
			return zero, lastErr
		}

		delay := config.CalculateDelay(attempt)
		if delay > 0 {
			select {
			case <-ctx.Done():
				return zero, fmt.Errorf("operation cancelled during retry delay: %w", ctx.Err())
			case <-time.After(delay):
			}
		}
	}

	return zero, fmt.Errorf("operation failed after %d attempts: %w", config.MaxAttempts, lastErr)
}

type RetryableSSHConnection struct {
	conn   Connection
	config *RetryConfig
}

func NewRetryableSSHConnection(conn Connection, config *RetryConfig) *RetryableSSHConnection {
	if config == nil {
		config = NewRetryConfig()
	}
	return &RetryableSSHConnection{
		conn:   conn,
		config: config,
	}
}

func (r *RetryableSSHConnection) Execute(ctx context.Context, command string) (*Result, error) {
	return WithRetryResult(ctx, r.config, func() (*Result, error) {
		return r.conn.Execute(ctx, command)
	})
}

func (r *RetryableSSHConnection) ExecuteArgs(ctx context.Context, cmd string, args ...string) (*Result, error) {
	return WithRetryResult(ctx, r.config, func() (*Result, error) {
		return r.conn.ExecuteArgs(ctx, cmd, args...)
	})
}

func (r *RetryableSSHConnection) Upload(ctx context.Context, localPath, remotePath string, mode fs.FileMode) error {
	return WithRetry(ctx, r.config, func() error {
		return r.conn.Upload(ctx, localPath, remotePath, mode)
	})
}

func (r *RetryableSSHConnection) Download(ctx context.Context, remotePath, localPath string) error {
	return WithRetry(ctx, r.config, func() error {
		return r.conn.Download(ctx, remotePath, localPath)
	})
}

func (r *RetryableSSHConnection) Close() error {
	return r.conn.Close()
}