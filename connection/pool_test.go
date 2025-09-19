package connection

import (
	"context"
	"testing"
	"time"
)

func TestNewPoolConfig(t *testing.T) {
	cfg := NewPoolConfig()
	if cfg.MaxConnections != 10 {
		t.Errorf("expected MaxConnections 10, got %d", cfg.MaxConnections)
	}
	if cfg.MaxIdleConnections != 5 {
		t.Errorf("expected MaxIdleConnections 5, got %d", cfg.MaxIdleConnections)
	}
	if cfg.MaxIdleTime != 5*time.Minute {
		t.Errorf("expected MaxIdleTime 5m, got %v", cfg.MaxIdleTime)
	}
}

func TestPooledConnectionExpiration(t *testing.T) {
	now := time.Now()
	pc := &pooledConnection{
		createdAt: now.Add(-10 * time.Minute),
		lastUsed:  now.Add(-2 * time.Minute),
		inUse:     false,
	}

	if !pc.isExpired(5*time.Minute, 1*time.Minute) {
		t.Error("connection should be expired due to max lifetime")
	}

	pc.createdAt = now.Add(-1 * time.Minute)
	if !pc.isExpired(10*time.Minute, 1*time.Minute) {
		t.Error("connection should be expired due to max idle time")
	}

	pc.lastUsed = now.Add(-30 * time.Second)
	if pc.isExpired(10*time.Minute, 1*time.Minute) {
		t.Error("connection should not be expired")
	}

	pc.inUse = true
	pc.lastUsed = now.Add(-2 * time.Minute)
	if pc.isExpired(10*time.Minute, 1*time.Minute) {
		t.Error("in-use connection should not be expired due to idle time")
	}
}

func TestConnectionPoolBasic(t *testing.T) {
	cfg := NewConfig("localhost", "testuser")
	cfg.Password = "testpass"
	cfg.AllowInsecureHostKey = true

	poolCfg := NewPoolConfig()
	poolCfg.MaxConnections = 2
	poolCfg.MaxIdleConnections = 1

	pool := NewConnectionPool(cfg, poolCfg)
	defer pool.Close()

	stats := pool.Stats()
	if stats.TotalConnections != 0 {
		t.Errorf("expected 0 total connections, got %d", stats.TotalConnections)
	}

	pool.Close()
	if err := pool.Close(); err != nil {
		t.Errorf("closing already closed pool should not error, got %v", err)
	}

	_, err := pool.Get(context.Background())
	if err != ErrPoolClosed {
		t.Errorf("expected ErrPoolClosed, got %v", err)
	}
}

func TestConnectionPoolStats(t *testing.T) {
	cfg := NewConfig("localhost", "testuser")
	cfg.Password = "testpass"
	cfg.AllowInsecureHostKey = true

	poolCfg := NewPoolConfig()
	poolCfg.MaxConnections = 3

	pool := NewConnectionPool(cfg, poolCfg)
	defer pool.Close()

	initialStats := pool.Stats()
	if initialStats.TotalConnections != 0 {
		t.Errorf("expected 0 initial connections, got %d", initialStats.TotalConnections)
	}
	if initialStats.ActiveConnections != 0 {
		t.Errorf("expected 0 active connections, got %d", initialStats.ActiveConnections)
	}
	if initialStats.IdleConnections != 0 {
		t.Errorf("expected 0 idle connections, got %d", initialStats.IdleConnections)
	}
}

func TestConnectionManager(t *testing.T) {
	retryConfig := NewRetryConfig()
	retryConfig.MaxAttempts = 1

	manager := NewConnectionManager(retryConfig)
	defer manager.CloseAll()

	cfg := NewConfig("localhost", "testuser")
	cfg.Password = "testpass"
	cfg.AllowInsecureHostKey = true

	_ = NewPoolConfig()

	stats := manager.GetStats()
	if len(stats) != 0 {
		t.Errorf("expected empty stats, got %d pools", len(stats))
	}

	err := manager.ClosePool(cfg)
	if err != nil {
		t.Errorf("closing non-existent pool should not error, got %v", err)
	}

	err = manager.CloseAll()
	if err != nil {
		t.Errorf("closing empty manager should not error, got %v", err)
	}
}

func TestManagedConnection(t *testing.T) {
	cfg := NewConfig("localhost", "testuser")
	cfg.Password = "testpass"
	cfg.AllowInsecureHostKey = true

	poolCfg := NewPoolConfig()
	retryConfig := NewRetryConfig()
	retryConfig.MaxAttempts = 1

	mc := NewManagedConnection(cfg, poolCfg, retryConfig)
	defer mc.Close()

	stats := mc.Stats()
	if len(stats) != 0 {
		t.Errorf("expected empty stats, got %d pools", len(stats))
	}

	err := mc.Close()
	if err != nil {
		t.Errorf("closing managed connection should not error, got %v", err)
	}
}