package connection

import (
	"context"
	"fmt"
	"io/fs"
	"sync"
)

type ConnectionManager struct {
	pools      map[string]*ConnectionPool
	retryConfig *RetryConfig
	mu         sync.RWMutex
}

func NewConnectionManager(retryConfig *RetryConfig) *ConnectionManager {
	if retryConfig == nil {
		retryConfig = NewRetryConfig()
	}
	return &ConnectionManager{
		pools:       make(map[string]*ConnectionPool),
		retryConfig: retryConfig,
	}
}

func (cm *ConnectionManager) getPoolKey(cfg *Config) string {
	return fmt.Sprintf("%s:%d@%s", cfg.User, cfg.Port, cfg.Host)
}

func (cm *ConnectionManager) GetConnection(ctx context.Context, cfg *Config, poolCfg *PoolConfig) (Connection, error) {
	cm.mu.RLock()
	poolKey := cm.getPoolKey(cfg)
	pool, exists := cm.pools[poolKey]
	cm.mu.RUnlock()

	if !exists {
		cm.mu.Lock()
		pool, exists = cm.pools[poolKey]
		if !exists {
			pool = NewConnectionPool(cfg, poolCfg)
			cm.pools[poolKey] = pool
		}
		cm.mu.Unlock()
	}

	pooledConn, err := pool.Get(ctx)
	if err != nil {
		return nil, err
	}

	return NewRetryableSSHConnection(pooledConn, cm.retryConfig), nil
}

func (cm *ConnectionManager) GetConnectionWithoutRetry(ctx context.Context, cfg *Config, poolCfg *PoolConfig) (Connection, error) {
	cm.mu.RLock()
	poolKey := cm.getPoolKey(cfg)
	pool, exists := cm.pools[poolKey]
	cm.mu.RUnlock()

	if !exists {
		cm.mu.Lock()
		pool, exists = cm.pools[poolKey]
		if !exists {
			pool = NewConnectionPool(cfg, poolCfg)
			cm.pools[poolKey] = pool
		}
		cm.mu.Unlock()
	}

	return pool.Get(ctx)
}

func (cm *ConnectionManager) GetStats() map[string]PoolStats {
	cm.mu.RLock()
	defer cm.mu.RUnlock()

	stats := make(map[string]PoolStats)
	for key, pool := range cm.pools {
		stats[key] = pool.Stats()
	}
	return stats
}

func (cm *ConnectionManager) ClosePool(cfg *Config) error {
	cm.mu.Lock()
	defer cm.mu.Unlock()

	poolKey := cm.getPoolKey(cfg)
	if pool, exists := cm.pools[poolKey]; exists {
		delete(cm.pools, poolKey)
		return pool.Close()
	}
	return nil
}

func (cm *ConnectionManager) CloseAll() error {
	cm.mu.Lock()
	defer cm.mu.Unlock()

	var errs []error
	for key, pool := range cm.pools {
		if err := pool.Close(); err != nil {
			errs = append(errs, fmt.Errorf("failed to close pool %s: %w", key, err))
		}
	}
	cm.pools = make(map[string]*ConnectionPool)

	if len(errs) > 0 {
		return fmt.Errorf("errors closing pools: %v", errs)
	}
	return nil
}

type ManagedConnection struct {
	manager *ConnectionManager
	cfg     *Config
	poolCfg *PoolConfig
}

func NewManagedConnection(cfg *Config, poolCfg *PoolConfig, retryConfig *RetryConfig) *ManagedConnection {
	return &ManagedConnection{
		manager: NewConnectionManager(retryConfig),
		cfg:     cfg,
		poolCfg: poolCfg,
	}
}

func (mc *ManagedConnection) Execute(ctx context.Context, command string) (*Result, error) {
	conn, err := mc.manager.GetConnection(ctx, mc.cfg, mc.poolCfg)
	if err != nil {
		return nil, err
	}
	defer conn.Close()

	return conn.Execute(ctx, command)
}

func (mc *ManagedConnection) ExecuteArgs(ctx context.Context, cmd string, args ...string) (*Result, error) {
	conn, err := mc.manager.GetConnection(ctx, mc.cfg, mc.poolCfg)
	if err != nil {
		return nil, err
	}
	defer conn.Close()

	return conn.ExecuteArgs(ctx, cmd, args...)
}

func (mc *ManagedConnection) Upload(ctx context.Context, localPath, remotePath string, mode fs.FileMode) error {
	conn, err := mc.manager.GetConnection(ctx, mc.cfg, mc.poolCfg)
	if err != nil {
		return err
	}
	defer conn.Close()

	return conn.Upload(ctx, localPath, remotePath, mode)
}

func (mc *ManagedConnection) Download(ctx context.Context, remotePath, localPath string) error {
	conn, err := mc.manager.GetConnection(ctx, mc.cfg, mc.poolCfg)
	if err != nil {
		return err
	}
	defer conn.Close()

	return conn.Download(ctx, remotePath, localPath)
}

func (mc *ManagedConnection) Close() error {
	return mc.manager.CloseAll()
}

func (mc *ManagedConnection) Stats() map[string]PoolStats {
	return mc.manager.GetStats()
}