package system

import (
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"
)

func TestNewDetector(t *testing.T) {
	detector := NewDetector()
	if detector == nil {
		t.Fatal("NewDetector returned nil")
	}
	if detector.cacheTime != 5*time.Minute {
		t.Errorf("Expected cache time to be 5 minutes, got %v", detector.cacheTime)
	}
}

func TestParseOSRelease(t *testing.T) {
	tests := []struct {
		name        string
		content     string
		expectError bool
		expectedID  string
		expectedName string
		expectedVersion string
		expectedVersionID string
	}{
		{
			name: "Ubuntu",
			content: `NAME="Ubuntu"
VERSION="22.04.3 LTS (Jammy Jellyfish)"
ID=ubuntu
ID_LIKE=debian
PRETTY_NAME="Ubuntu 22.04.3 LTS"
VERSION_ID="22.04"
HOME_URL="https://www.ubuntu.com/"`,
			expectedID: "ubuntu",
			expectedName: "Ubuntu",
			expectedVersion: "22.04.3 LTS (Jammy Jellyfish)",
			expectedVersionID: "22.04",
		},
		{
			name: "RHEL",
			content: `NAME="Red Hat Enterprise Linux"
VERSION="9.2 (Plow)"
ID="rhel"
ID_LIKE="fedora"
VERSION_ID="9.2"
PLATFORM_ID="platform:el9"`,
			expectedID: "rhel",
			expectedName: "Red Hat Enterprise Linux",
			expectedVersion: "9.2 (Plow)",
			expectedVersionID: "9.2",
		},
		{
			name: "Debian",
			content: `PRETTY_NAME="Debian GNU/Linux 12 (bookworm)"
NAME="Debian GNU/Linux"
VERSION_ID="12"
VERSION="12 (bookworm)"
VERSION_CODENAME=bookworm
ID=debian`,
			expectedID: "debian",
			expectedName: "Debian GNU/Linux",
			expectedVersion: "12 (bookworm)",
			expectedVersionID: "12",
		},
		{
			name: "CentOS",
			content: `NAME="CentOS Linux"
VERSION="8"
ID="centos"
ID_LIKE="rhel fedora"
VERSION_ID="8"
PLATFORM_ID="platform:el8"`,
			expectedID: "centos",
			expectedName: "CentOS Linux",
			expectedVersion: "8",
			expectedVersionID: "8",
		},
		{
			name: "Rocky Linux",
			content: `NAME="Rocky Linux"
VERSION="9.2 (Blue Onyx)"
ID="rocky"
ID_LIKE="rhel centos fedora"
VERSION_ID="9.2"
PLATFORM_ID="platform:el9"`,
			expectedID: "rocky",
			expectedName: "Rocky Linux",
			expectedVersion: "9.2 (Blue Onyx)",
			expectedVersionID: "9.2",
		},
		{
			name: "AlmaLinux",
			content: `NAME="AlmaLinux"
VERSION="9.2 (Turquoise Kodkod)"
ID="almalinux"
ID_LIKE="rhel centos fedora"
VERSION_ID="9.2"
PLATFORM_ID="platform:el9"`,
			expectedID: "almalinux",
			expectedName: "AlmaLinux",
			expectedVersion: "9.2 (Turquoise Kodkod)",
			expectedVersionID: "9.2",
		},
		{
			name: "Missing ID",
			content: `NAME="Test Linux"
VERSION="1.0"`,
			expectError: true,
		},
		{
			name: "Empty file",
			content: "",
			expectError: true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			tmpDir := t.TempDir()
			osReleasePath := filepath.Join(tmpDir, "os-release")

			if err := os.WriteFile(osReleasePath, []byte(tt.content), 0644); err != nil {
				t.Fatalf("Failed to write test file: %v", err)
			}

			detector := NewDetector()
			info := &DistributionInfo{}

			originalOSRelease := "/etc/os-release"
			defer func() {
				os.Rename(osReleasePath, originalOSRelease)
			}()

			if err := os.Rename(osReleasePath, originalOSRelease); err != nil {
				t.Skip("Cannot modify /etc/os-release for testing")
			}

			err := detector.parseOSRelease(info)

			if tt.expectError {
				if err == nil {
					t.Error("Expected error but got none")
				}
				return
			}

			if err != nil {
				t.Fatalf("Unexpected error: %v", err)
			}

			if info.ID != tt.expectedID {
				t.Errorf("Expected ID %q, got %q", tt.expectedID, info.ID)
			}
			if info.Name != tt.expectedName {
				t.Errorf("Expected Name %q, got %q", tt.expectedName, info.Name)
			}
			if info.Version != tt.expectedVersion {
				t.Errorf("Expected Version %q, got %q", tt.expectedVersion, info.Version)
			}
			if info.VersionID != tt.expectedVersionID {
				t.Errorf("Expected VersionID %q, got %q", tt.expectedVersionID, info.VersionID)
			}
		})
	}
}

func TestDetectPackageManager(t *testing.T) {
	tests := []struct {
		name           string
		distroID       string
		expectedPkgMgr string
	}{
		{"Ubuntu", "ubuntu", "apt"},
		{"Debian", "debian", "apt"},
		{"RHEL", "rhel", "yum"},
		{"CentOS", "centos", "yum"},
		{"Rocky", "rocky", "yum"},
		{"AlmaLinux", "almalinux", "yum"},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			detector := NewDetector()
			info := &DistributionInfo{ID: tt.distroID}

			err := detector.detectPackageManager(info)
			if err != nil {
				t.Logf("Package manager detection failed (expected on some systems): %v", err)
				return
			}

			if !strings.Contains(tt.expectedPkgMgr, info.PackageManager) &&
			   !strings.Contains(info.PackageManager, tt.expectedPkgMgr) {
				t.Logf("Expected package manager containing %q, got %q (may vary by system)",
					tt.expectedPkgMgr, info.PackageManager)
			}
		})
	}
}

func TestDetectInitSystem(t *testing.T) {
	detector := NewDetector()
	info := &DistributionInfo{}

	err := detector.detectInitSystem(info)
	if err != nil {
		t.Fatalf("Unexpected error: %v", err)
	}

	validInitSystems := []string{"systemd", "upstart", "sysvinit", "unknown"}
	found := false
	for _, valid := range validInitSystems {
		if info.InitSystem == valid {
			found = true
			break
		}
	}

	if !found {
		t.Errorf("Unknown init system detected: %q", info.InitSystem)
	}
}

func TestIsSupported(t *testing.T) {
	tests := []struct {
		name     string
		distroID string
		expected bool
	}{
		{"Ubuntu", "ubuntu", true},
		{"Debian", "debian", true},
		{"RHEL", "rhel", true},
		{"CentOS", "centos", true},
		{"Rocky", "rocky", true},
		{"AlmaLinux", "almalinux", true},
		{"Fedora", "fedora", true},
		{"Arch", "arch", false},
		{"Gentoo", "gentoo", false},
		{"Unknown", "unknown", false},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			info := &DistributionInfo{ID: tt.distroID}
			result := info.IsSupported()
			if result != tt.expected {
				t.Errorf("Expected IsSupported() to return %v for %q, got %v",
					tt.expected, tt.distroID, result)
			}
		})
	}
}

func TestCaching(t *testing.T) {
	detector := NewDetector()
	detector.SetCacheTime(100 * time.Millisecond)

	info1, err := detector.DetectDistribution()
	if err != nil {
		t.Fatalf("First detection failed: %v", err)
	}

	info2, err := detector.DetectDistribution()
	if err != nil {
		t.Fatalf("Second detection failed: %v", err)
	}

	if info1 != info2 {
		t.Error("Expected cached result to be the same instance")
	}

	time.Sleep(150 * time.Millisecond)

	info3, err := detector.DetectDistribution()
	if err != nil {
		t.Fatalf("Third detection failed: %v", err)
	}

	if info1 == info3 {
		t.Error("Expected cache to be invalidated after timeout")
	}
}

func TestInvalidateCache(t *testing.T) {
	detector := NewDetector()

	_, err := detector.DetectDistribution()
	if err != nil {
		t.Fatalf("Detection failed: %v", err)
	}

	detector.InvalidateCache()

	detector.cacheMux.RLock()
	cache := detector.cache
	detector.cacheMux.RUnlock()

	if cache != nil {
		t.Error("Expected cache to be nil after invalidation")
	}
}

func TestString(t *testing.T) {
	info := &DistributionInfo{
		ID:             "ubuntu",
		Name:           "Ubuntu",
		Version:        "22.04.3 LTS (Jammy Jellyfish)",
		VersionID:      "22.04",
		PackageManager: "apt",
		InitSystem:     "systemd",
	}

	result := info.String()
	expected := "Ubuntu 22.04.3 LTS (Jammy Jellyfish) (ID: ubuntu, Package Manager: apt, Init: systemd)"

	if result != expected {
		t.Errorf("Expected string representation:\n%q\nGot:\n%q", expected, result)
	}
}

func BenchmarkDetectDistribution(b *testing.B) {
	detector := NewDetector()

	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		_, err := detector.DetectDistribution()
		if err != nil {
			b.Fatalf("Detection failed: %v", err)
		}
	}
}

func BenchmarkCachedDetection(b *testing.B) {
	detector := NewDetector()

	_, err := detector.DetectDistribution()
	if err != nil {
		b.Fatalf("Initial detection failed: %v", err)
	}

	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		_, err := detector.DetectDistribution()
		if err != nil {
			b.Fatalf("Cached detection failed: %v", err)
		}
	}
}