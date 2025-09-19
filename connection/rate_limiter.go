package connection

import (
	"context"
	"errors"
	"fmt"
	"time"

	"golang.org/x/time/rate"
)

type RateLimiter struct {
	limiter *rate.Limiter
	timeout time.Duration
}

const (
	defaultRateLimit      = 10.0
	defaultBurstLimit     = 20
	defaultRequestTimeout = 30 * time.Second
)

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