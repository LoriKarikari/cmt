package connection

import (
	"errors"
	"sync"
	"time"
)

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

const (
	defaultFailureThreshold = 5
	defaultTimeout          = 60 * time.Second
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