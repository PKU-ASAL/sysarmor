package tetragon

import (
	"crypto/sha256"
	"encoding/hex"
	"fmt"
	"os"
	"path/filepath"
	"runtime"
	"strings"
	"testing"
)

func TestVerifyBundleChecksManifestAndBinaries(t *testing.T) {
	dir := writeBundle(t, "v1.2.3", "tetragon-bin", "tetra-bin")
	got, err := VerifyBundle(BundleConfig{BundleDir: dir})
	if err != nil {
		t.Fatalf("VerifyBundle() error = %v", err)
	}
	if got.Version != "v1.2.3" {
		t.Fatalf("version = %q", got.Version)
	}
	if got.TetragonPath != filepath.Join(dir, "bin", "tetragon") || got.TetraPath != filepath.Join(dir, "bin", "tetra") {
		t.Fatalf("paths = %+v", got)
	}
}

func TestVerifyBundleRejectsChecksumMismatch(t *testing.T) {
	dir := writeBundle(t, "v1.2.3", "tetragon-bin", "tetra-bin")
	if err := os.WriteFile(filepath.Join(dir, "bin", "tetra"), []byte("changed"), 0o755); err != nil {
		t.Fatal(err)
	}
	_, err := VerifyBundle(BundleConfig{BundleDir: dir})
	if err == nil || !strings.Contains(err.Error(), "checksum mismatch") {
		t.Fatalf("VerifyBundle() error = %v, want checksum mismatch", err)
	}
}

func TestCapabilityVerifiesBundleAndUpdatesHealth(t *testing.T) {
	dir := writeBundle(t, "v1.2.3", "tetragon-bin", "tetra-bin")
	backend := NewBackendWithBundle("policy.yaml", "", "", BundleConfig{BundleDir: dir})
	capability, err := backend.Capability(nil)
	if err != nil {
		t.Fatalf("Capability() error = %v", err)
	}
	if capability.Version != "v1.2.3" {
		t.Fatalf("capability version = %q", capability.Version)
	}
	health, err := backend.Health(nil)
	if err != nil {
		t.Fatalf("Health() error = %v", err)
	}
	if !health.Installed || health.Version != "v1.2.3" {
		t.Fatalf("health = %+v", health)
	}
}

func TestCapabilityInstallsBundleWhenInstallDirConfigured(t *testing.T) {
	dir := writeBundle(t, "v1.2.3", "tetragon-bin", "tetra-bin")
	installDir := filepath.Join(t.TempDir(), "sensors")
	if _, err := InstallBundle(BundleConfig{BundleDir: dir, InstallDir: installDir}); err != nil {
		t.Fatal(err)
	}
	backend := NewBackendWithBundle("policy.yaml", "", "", BundleConfig{BundleDir: dir, InstallDir: installDir})
	if _, err := backend.Capability(nil); err != nil {
		t.Fatalf("Capability() verification error = %v", err)
	}
	versionDir := filepath.Join(installDir, "tetragon", "v1.2.3")
	if backend.Bundle.TetraPath != filepath.Join(versionDir, "bin", "tetra") || backend.Bundle.TetragonPath != filepath.Join(versionDir, "bin", "tetragon") {
		t.Fatalf("verified executable paths were not bound: %+v", backend.Bundle)
	}
	assertFileContains(t, filepath.Join(installDir, "tetragon", "current", "bin", "tetragon"), "tetragon-bin")
	assertFileContains(t, filepath.Join(installDir, "tetragon", "current", "bin", "tetra"), "tetra-bin")
}

func TestCapabilityRejectsUnstagedBundleWhenInstallDirConfigured(t *testing.T) {
	dir := writeBundle(t, "v1.2.3", "tetragon-bin", "tetra-bin")
	installDir := filepath.Join(t.TempDir(), "sensors")
	backend := NewBackendWithBundle("policy.yaml", "", "", BundleConfig{BundleDir: dir, InstallDir: installDir})
	if _, err := backend.Capability(nil); err == nil || !strings.Contains(err.Error(), "staged") {
		t.Fatalf("Capability() error = %v, want staged bundle error", err)
	}
	if _, err := os.Stat(installDir); !os.IsNotExist(err) {
		t.Fatalf("agent startup created install directory: err=%v", err)
	}
}

func TestCapabilityRejectsCurrentOutsideInstallDirectory(t *testing.T) {
	external := writeBundle(t, "v1.2.3", "tetragon-bin", "tetra-bin")
	installDir := filepath.Join(t.TempDir(), "sensors")
	root := filepath.Join(installDir, "tetragon")
	if err := os.MkdirAll(root, 0o755); err != nil {
		t.Fatal(err)
	}
	if err := os.Symlink(external, filepath.Join(root, "current")); err != nil {
		t.Fatal(err)
	}
	backend := NewBackendWithBundle("policy.yaml", "", "", BundleConfig{BundleDir: external, InstallDir: installDir})
	if _, err := backend.Capability(nil); err == nil || !strings.Contains(err.Error(), "outside") {
		t.Fatalf("Capability() error = %v, want outside install directory", err)
	}
}

func TestInstallBundleCopiesVersionAndPointsCurrent(t *testing.T) {
	dir := writeBundle(t, "v1.2.3", "tetragon-bin", "tetra-bin")
	installDir := filepath.Join(t.TempDir(), "sensors")
	got, err := InstallBundle(BundleConfig{BundleDir: dir, InstallDir: installDir})
	if err != nil {
		t.Fatalf("InstallBundle() error = %v", err)
	}
	if got.Version != "v1.2.3" {
		t.Fatalf("version = %q", got.Version)
	}
	if got.InstallPath != filepath.Join(installDir, "tetragon", "v1.2.3") {
		t.Fatalf("install path = %q", got.InstallPath)
	}
	assertFileContains(t, filepath.Join(got.InstallPath, "bin", "tetragon"), "tetragon-bin")
	assertFileContains(t, filepath.Join(got.InstallPath, "bin", "tetra"), "tetra-bin")
	assertFileContains(t, got.TetragonPath, "tetragon-bin")
	assertFileContains(t, got.TetraPath, "tetra-bin")
	if runtime.GOOS != "windows" {
		target, err := os.Readlink(got.CurrentPath)
		if err != nil {
			t.Fatalf("Readlink(current) error = %v", err)
		}
		if target != "v1.2.3" {
			t.Fatalf("current target = %q", target)
		}
	}
}

func TestInstallBundleIsIdempotent(t *testing.T) {
	dir := writeBundle(t, "v1.2.3", "tetragon-bin", "tetra-bin")
	installDir := filepath.Join(t.TempDir(), "sensors")
	first, err := InstallBundle(BundleConfig{BundleDir: dir, InstallDir: installDir})
	if err != nil {
		t.Fatalf("first InstallBundle() error = %v", err)
	}
	second, err := InstallBundle(BundleConfig{BundleDir: dir, InstallDir: installDir})
	if err != nil {
		t.Fatalf("second InstallBundle() error = %v", err)
	}
	if first.InstallPath != second.InstallPath || first.CurrentPath != second.CurrentPath {
		t.Fatalf("installations differ: first=%+v second=%+v", first, second)
	}
	assertFileContains(t, second.TetraPath, "tetra-bin")
}

func writeBundle(t *testing.T, version, tetragonContent, tetraContent string) string {
	t.Helper()
	dir := t.TempDir()
	binDir := filepath.Join(dir, "bin")
	if err := os.MkdirAll(binDir, 0o755); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(binDir, "tetragon"), []byte(tetragonContent), 0o755); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(binDir, "tetra"), []byte(tetraContent), 0o755); err != nil {
		t.Fatal(err)
	}
	manifest := fmt.Sprintf(`{
  "version": %q,
  "files": {
    "bin/tetragon": {"sha256": %q},
    "bin/tetra": {"sha256": %q}
  }
}`, version, sha256Hex(tetragonContent), sha256Hex(tetraContent))
	if err := os.WriteFile(filepath.Join(dir, "manifest.json"), []byte(manifest), 0o644); err != nil {
		t.Fatal(err)
	}
	return dir
}

func assertFileContains(t *testing.T, path, want string) {
	t.Helper()
	data, err := os.ReadFile(path)
	if err != nil {
		t.Fatalf("ReadFile(%s) error = %v", path, err)
	}
	if string(data) != want {
		t.Fatalf("file %s = %q, want %q", path, string(data), want)
	}
}

func sha256Hex(data string) string {
	sum := sha256.Sum256([]byte(data))
	return hex.EncodeToString(sum[:])
}
