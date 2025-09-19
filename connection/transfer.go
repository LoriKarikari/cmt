package connection

import (
	"context"
	"errors"
	"fmt"
	"io"
	"io/fs"
	"os"
	"path/filepath"
	"strings"
)

var (
	ErrTransferFailed = errors.New("file transfer failed")
	ErrInvalidPath    = errors.New("invalid path")
)

const (
	maxTransferSize = 100 * 1024 * 1024
)

func (s *SSHConnection) Upload(ctx context.Context, localPath, remotePath string, mode fs.FileMode) error {
	if err := s.rateLimiter.Wait(ctx); err != nil {
		return err
	}
	return s.circuitBreaker.Call(func() error {
		if s.sftpClient != nil {
			return s.uploadSFTP(localPath, remotePath, mode)
		}
		return s.uploadInternal(ctx, localPath, remotePath, mode)
	})
}

func (s *SSHConnection) Download(ctx context.Context, remotePath, localPath string) error {
	if err := s.rateLimiter.Wait(ctx); err != nil {
		return err
	}
	return s.circuitBreaker.Call(func() error {
		if s.sftpClient != nil {
			return s.downloadSFTP(remotePath, localPath)
		}
		return s.downloadInternal(ctx, remotePath, localPath)
	})
}

func (s *SSHConnection) uploadSFTP(localPath, remotePath string, mode fs.FileMode) error {
	src, err := os.Open(localPath)
	if err != nil {
		return fmt.Errorf("open local file: %w", err)
	}
	defer src.Close()
	dst, err := s.sftpClient.Create(remotePath)
	if err != nil {
		return fmt.Errorf("create remote file: %w", err)
	}
	defer dst.Close()
	if _, err := io.Copy(dst, src); err != nil {
		return fmt.Errorf("copy to remote: %w", err)
	}
	return s.sftpClient.Chmod(remotePath, mode)
}

func (s *SSHConnection) downloadSFTP(remotePath, localPath string) error {
	src, err := s.sftpClient.Open(remotePath)
	if err != nil {
		return fmt.Errorf("open remote file: %w", err)
	}
	defer src.Close()
	dst, err := os.Create(localPath)
	if err != nil {
		return fmt.Errorf("create local file: %w", err)
	}
	defer dst.Close()
	_, err = io.Copy(dst, src)
	return err
}

func (s *SSHConnection) uploadInternal(ctx context.Context, localPath, remotePath string, mode fs.FileMode) error {
	info, err := os.Stat(localPath)
	if err != nil {
		return fmt.Errorf("%w: cannot stat local file: %v", ErrInvalidPath, err)
	}
	if info.Size() > maxTransferSize {
		return fmt.Errorf("%w: file too large (%d > %d bytes)",
			ErrTransferFailed, info.Size(), maxTransferSize)
	}
	if strings.Contains(remotePath, "..") || strings.Contains(remotePath, "~") {
		return fmt.Errorf("%w: invalid remote path", ErrInvalidPath)
	}
	session, err := s.client.NewSession()
	if err != nil {
		return fmt.Errorf("%w: failed to create session: %v", ErrSessionFailed, err)
	}
	defer session.Close()
	stdin, err := session.StdinPipe()
	if err != nil {
		return fmt.Errorf("%w: failed to create stdin pipe: %v", ErrTransferFailed, err)
	}
	defer stdin.Close()
	targetDir := filepath.Dir(remotePath)
	baseName := filepath.Base(remotePath)
	go func() {
		defer stdin.Close()
		fmt.Fprintf(stdin, "C%#o %d %s\n", mode.Perm(), info.Size(), baseName)
		file, err := os.Open(localPath)
		if err != nil {
			return
		}
		defer file.Close()
		if _, err := io.Copy(stdin, file); err != nil {
			return
		}
		fmt.Fprint(stdin, "\x00")
	}()
	cmd := fmt.Sprintf("scp -t %s", quoteArg(targetDir))
	if err := session.Run(cmd); err != nil {
		return fmt.Errorf("%w: scp command failed: %v", ErrTransferFailed, err)
	}
	return nil
}

func (s *SSHConnection) downloadInternal(ctx context.Context, remotePath, localPath string) error {
	if strings.Contains(remotePath, "..") || strings.Contains(remotePath, "~") {
		return fmt.Errorf("%w: invalid remote path", ErrInvalidPath)
	}
	session, err := s.client.NewSession()
	if err != nil {
		return fmt.Errorf("%w: failed to create session: %v", ErrSessionFailed, err)
	}
	defer session.Close()
	stdout, err := session.StdoutPipe()
	if err != nil {
		return fmt.Errorf("%w: failed to create stdout pipe: %v", ErrTransferFailed, err)
	}
	cmd := fmt.Sprintf("scp -f %s", quoteArg(remotePath))
	localFile, err := os.Create(localPath)
	if err != nil {
		return fmt.Errorf("%w: failed to create local file: %v", ErrTransferFailed, err)
	}
	defer localFile.Close()
	stdin, err := session.StdinPipe()
	if err != nil {
		return fmt.Errorf("%w: failed to create stdin pipe: %v", ErrTransferFailed, err)
	}
	go func() {
		defer stdin.Close()
		fmt.Fprint(stdin, "\x00")
	}()
	if err := session.Start(cmd); err != nil {
		return fmt.Errorf("%w: failed to start scp: %v", ErrTransferFailed, err)
	}
	buf := make([]byte, bufferSize)
	for {
		n, err := stdout.Read(buf)
		if n > 0 {
			if _, werr := localFile.Write(buf[:n]); werr != nil {
				return fmt.Errorf("%w: write error: %v", ErrTransferFailed, werr)
			}
		}
		if err == io.EOF {
			break
		}
		if err != nil {
			return fmt.Errorf("%w: read error: %v", ErrTransferFailed, err)
		}
	}
	if err := session.Wait(); err != nil {
		return fmt.Errorf("%w: scp wait error: %v", ErrTransferFailed, err)
	}
	return nil
}