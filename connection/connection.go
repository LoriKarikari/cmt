package connection

import (
	"context"
	"fmt"
	"io/fs"
)

type ConnectionError struct {
	Op   string
	Err  error
	Host string
}

func (e *ConnectionError) Error() string {
	if e.Host != "" {
		return fmt.Sprintf("connection error [%s@%s]: %v", e.Op, e.Host, e.Err)
	}
	return fmt.Sprintf("connection error [%s]: %v", e.Op, e.Err)
}

func (e *ConnectionError) Unwrap() error {
	return e.Err
}

type Connection interface {
	Execute(ctx context.Context, command string) (*Result, error)
	ExecuteArgs(ctx context.Context, cmd string, args ...string) (*Result, error)
	Upload(ctx context.Context, localPath, remotePath string, mode fs.FileMode) error
	Download(ctx context.Context, remotePath, localPath string) error
	Close() error
}

type Result struct {
	Stdout   string
	Stderr   string
	ExitCode int
}

func (r *Result) Success() bool {
	return r.ExitCode == 0
}
