package connection

import (
	"context"
	"errors"
	"fmt"
	"io/fs"
	"sync"
	"time"
)

var (
	ErrPoolClosed    = errors.New("connection pool is closed")
	ErrPoolExhausted = errors.New("connection pool exhausted")
)

type PoolConfig struct {
	MaxConnections     int
	MaxIdleConnections int
	MaxIdleTime        time.Duration
	MaxLifetime        time.Duration
	HealthCheckPeriod  time.Duration
}

func NewPoolConfig() *PoolConfig {
	return &PoolConfig{
		MaxConnections:     10,
		MaxIdleConnections: 5,
		MaxIdleTime:        5 * time.Minute,
		MaxLifetime:        30 * time.Minute,
		HealthCheckPeriod:  30 * time.Second,
	}
}

type pooledConnection struct {
	conn      *SSHConnection
	createdAt time.Time
	lastUsed  time.Time
	inUse     bool
}

func (pc *pooledConnection) isExpired(maxLifetime, maxIdleTime time.Duration) bool {
	now := time.Now()
	if maxLifetime > 0 && now.Sub(pc.createdAt) > maxLifetime {
		return true
	}
	if maxIdleTime > 0 && !pc.inUse && now.Sub(pc.lastUsed) > maxIdleTime {
		return true
	}
	return false
}

type ConnectionPool struct {
	cfg         *Config
	poolCfg     *PoolConfig
	connections []*pooledConnection
	mu          sync.RWMutex
	closed      bool
	stopCleanup chan struct{}
}

func NewConnectionPool(cfg *Config, poolCfg *PoolConfig) *ConnectionPool {
	if poolCfg == nil {
		poolCfg = NewPoolConfig()
	}

	pool := &ConnectionPool{
		cfg:         cfg,
		poolCfg:     poolCfg,
		connections: make([]*pooledConnection, 0, poolCfg.MaxConnections),
		stopCleanup: make(chan struct{}),
	}

	go pool.cleanup()
	return pool
}

func (p *ConnectionPool) Get(ctx context.Context) (*PooledSSHConnection, error) {
	p.mu.Lock()
	defer p.mu.Unlock()

	if p.closed {
		return nil, ErrPoolClosed
	}

	for i, pc := range p.connections {
		if !pc.inUse && !pc.isExpired(p.poolCfg.MaxLifetime, p.poolCfg.MaxIdleTime) {
			pc.inUse = true
			pc.lastUsed = time.Now()
			return &PooledSSHConnection{
				conn: pc.conn,
				pool: p,
				pc:   pc,
			}, nil
		}
		if pc.isExpired(p.poolCfg.MaxLifetime, p.poolCfg.MaxIdleTime) {
			pc.conn.Close()
			p.connections = append(p.connections[:i], p.connections[i+1:]...)
		}
	}

	if len(p.connections) >= p.poolCfg.MaxConnections {
		return nil, ErrPoolExhausted
	}

	conn, err := NewSSHConnection(p.cfg)
	if err != nil {
		return nil, fmt.Errorf("failed to create new connection: %w", err)
	}

	pc := &pooledConnection{
		conn:      conn,
		createdAt: time.Now(),
		lastUsed:  time.Now(),
		inUse:     true,
	}

	p.connections = append(p.connections, pc)

	return &PooledSSHConnection{
		conn: conn,
		pool: p,
		pc:   pc,
	}, nil
}

func (p *ConnectionPool) put(pc *pooledConnection) {
	p.mu.Lock()
	defer p.mu.Unlock()

	if p.closed {
		pc.conn.Close()
		return
	}

	pc.inUse = false
	pc.lastUsed = time.Now()

	idleCount := 0
	for _, conn := range p.connections {
		if !conn.inUse {
			idleCount++
		}
	}

	if idleCount > p.poolCfg.MaxIdleConnections {
		for i, conn := range p.connections {
			if !conn.inUse {
				conn.conn.Close()
				p.connections = append(p.connections[:i], p.connections[i+1:]...)
				break
			}
		}
	}
}

func (p *ConnectionPool) cleanup() {
	ticker := time.NewTicker(p.poolCfg.HealthCheckPeriod)
	defer ticker.Stop()

	for {
		select {
		case <-ticker.C:
			p.cleanupExpired()
		case <-p.stopCleanup:
			return
		}
	}
}

func (p *ConnectionPool) cleanupExpired() {
	p.mu.Lock()
	defer p.mu.Unlock()

	var active []*pooledConnection
	for _, pc := range p.connections {
		if pc.isExpired(p.poolCfg.MaxLifetime, p.poolCfg.MaxIdleTime) {
			if !pc.inUse {
				pc.conn.Close()
			}
		} else {
			active = append(active, pc)
		}
	}
	p.connections = active
}

func (p *ConnectionPool) Close() error {
	p.mu.Lock()
	defer p.mu.Unlock()

	if p.closed {
		return nil
	}

	p.closed = true
	close(p.stopCleanup)

	for _, pc := range p.connections {
		pc.conn.Close()
	}
	p.connections = nil

	return nil
}

func (p *ConnectionPool) Stats() PoolStats {
	p.mu.RLock()
	defer p.mu.RUnlock()

	stats := PoolStats{
		TotalConnections: len(p.connections),
	}

	for _, pc := range p.connections {
		if pc.inUse {
			stats.ActiveConnections++
		} else {
			stats.IdleConnections++
		}
	}

	return stats
}

type PoolStats struct {
	TotalConnections  int
	ActiveConnections int
	IdleConnections   int
}

type PooledSSHConnection struct {
	conn *SSHConnection
	pool *ConnectionPool
	pc   *pooledConnection
}

func (psc *PooledSSHConnection) Execute(ctx context.Context, command string) (*Result, error) {
	return psc.conn.Execute(ctx, command)
}

func (psc *PooledSSHConnection) ExecuteArgs(ctx context.Context, cmd string, args ...string) (*Result, error) {
	return psc.conn.ExecuteArgs(ctx, cmd, args...)
}

func (psc *PooledSSHConnection) Upload(ctx context.Context, localPath, remotePath string, mode fs.FileMode) error {
	return psc.conn.Upload(ctx, localPath, remotePath, mode)
}

func (psc *PooledSSHConnection) Download(ctx context.Context, remotePath, localPath string) error {
	return psc.conn.Download(ctx, remotePath, localPath)
}

func (psc *PooledSSHConnection) Close() error {
	if psc.pool != nil {
		psc.pool.put(psc.pc)
		psc.pool = nil
		psc.pc = nil
	}
	return nil
}