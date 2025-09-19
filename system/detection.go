package system

import (
	"bufio"
	"fmt"
	"os"
	"os/exec"
	"strings"
	"sync"
	"time"
)

type DistributionInfo struct {
	ID               string
	Name             string
	Version          string
	VersionID        string
	PackageManager   string
	InitSystem       string
	DetectedAt       time.Time
}

type Detector struct {
	cache     *DistributionInfo
	cacheMux  sync.RWMutex
	cacheTime time.Duration
}

func NewDetector() *Detector {
	return &Detector{
		cacheTime: 5 * time.Minute,
	}
}

func (d *Detector) DetectDistribution() (*DistributionInfo, error) {
	d.cacheMux.RLock()
	if d.cache != nil && time.Since(d.cache.DetectedAt) < d.cacheTime {
		defer d.cacheMux.RUnlock()
		return d.cache, nil
	}
	d.cacheMux.RUnlock()

	d.cacheMux.Lock()
	defer d.cacheMux.Unlock()

	if d.cache != nil && time.Since(d.cache.DetectedAt) < d.cacheTime {
		return d.cache, nil
	}

	info, err := d.detectDistribution()
	if err != nil {
		return nil, err
	}

	d.cache = info
	return info, nil
}

func (d *Detector) detectDistribution() (*DistributionInfo, error) {
	info := &DistributionInfo{
		DetectedAt: time.Now(),
	}

	if err := d.parseOSRelease(info); err != nil {
		return nil, fmt.Errorf("failed to parse os-release: %w", err)
	}

	if err := d.detectPackageManager(info); err != nil {
		return nil, fmt.Errorf("failed to detect package manager: %w", err)
	}

	if err := d.detectInitSystem(info); err != nil {
		return nil, fmt.Errorf("failed to detect init system: %w", err)
	}

	return info, nil
}

func (d *Detector) parseOSRelease(info *DistributionInfo) error {
	file, err := os.Open("/etc/os-release")
	if err != nil {
		return fmt.Errorf("failed to open /etc/os-release: %w", err)
	}
	defer file.Close()

	scanner := bufio.NewScanner(file)
	for scanner.Scan() {
		line := strings.TrimSpace(scanner.Text())
		if line == "" || strings.HasPrefix(line, "#") {
			continue
		}

		parts := strings.SplitN(line, "=", 2)
		if len(parts) != 2 {
			continue
		}

		key := strings.TrimSpace(parts[0])
		value := strings.Trim(strings.TrimSpace(parts[1]), `"`)

		switch key {
		case "ID":
			info.ID = value
		case "NAME":
			info.Name = value
		case "VERSION":
			info.Version = value
		case "VERSION_ID":
			info.VersionID = value
		}
	}

	if err := scanner.Err(); err != nil {
		return fmt.Errorf("error reading os-release: %w", err)
	}

	if info.ID == "" {
		return fmt.Errorf("distribution ID not found in os-release")
	}

	return nil
}

func (d *Detector) detectPackageManager(info *DistributionInfo) error {
	packageManagers := []struct {
		name    string
		command string
		distros []string
	}{
		{"apt", "apt", []string{"ubuntu", "debian"}},
		{"yum", "yum", []string{"rhel", "centos", "rocky", "almalinux"}},
		{"dnf", "dnf", []string{"fedora", "rhel", "centos", "rocky", "almalinux"}},
	}

	for _, pm := range packageManagers {
		for _, distro := range pm.distros {
			if strings.Contains(strings.ToLower(info.ID), distro) {
				if d.commandExists(pm.command) {
					info.PackageManager = pm.name
					return nil
				}
			}
		}
	}

	for _, pm := range packageManagers {
		if d.commandExists(pm.command) {
			info.PackageManager = pm.name
			return nil
		}
	}

	return fmt.Errorf("no supported package manager found")
}

func (d *Detector) detectInitSystem(info *DistributionInfo) error {
	initSystems := []struct {
		name      string
		checkPath string
		checkCmd  string
	}{
		{"systemd", "/run/systemd/system", "systemctl"},
		{"upstart", "/sbin/upstart", "initctl"},
		{"sysvinit", "/etc/init.d", "service"},
	}

	for _, init := range initSystems {
		if init.checkPath != "" {
			if _, err := os.Stat(init.checkPath); err == nil {
				if init.checkCmd == "" || d.commandExists(init.checkCmd) {
					info.InitSystem = init.name
					return nil
				}
			}
		}
		if init.checkCmd != "" && d.commandExists(init.checkCmd) {
			info.InitSystem = init.name
			return nil
		}
	}

	info.InitSystem = "unknown"
	return nil
}

func (d *Detector) commandExists(cmd string) bool {
	_, err := exec.LookPath(cmd)
	return err == nil
}

func (d *Detector) InvalidateCache() {
	d.cacheMux.Lock()
	defer d.cacheMux.Unlock()
	d.cache = nil
}

func (d *Detector) SetCacheTime(duration time.Duration) {
	d.cacheMux.Lock()
	defer d.cacheMux.Unlock()
	d.cacheTime = duration
}

func (info *DistributionInfo) IsSupported() bool {
	supportedDistros := []string{
		"ubuntu", "debian", "rhel", "centos", "rocky", "almalinux", "fedora",
	}

	idLower := strings.ToLower(info.ID)
	for _, supported := range supportedDistros {
		if strings.Contains(idLower, supported) {
			return true
		}
	}
	return false
}

func (info *DistributionInfo) String() string {
	return fmt.Sprintf("%s %s (ID: %s, Package Manager: %s, Init: %s)",
		info.Name, info.Version, info.ID, info.PackageManager, info.InitSystem)
}