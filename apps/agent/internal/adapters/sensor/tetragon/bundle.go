package tetragon

import (
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"runtime"
	"strings"
)

type BundleConfig struct {
	BundleDir    string
	InstallDir   string
	TetraPath    string
	TetragonPath string
}

type BundleManifest struct {
	Version string                  `json:"version"`
	Files   map[string]ManifestFile `json:"files"`
}

type ManifestFile struct {
	SHA256 string `json:"sha256"`
}

type BundleVerification struct {
	Version      string
	TetraPath    string
	TetragonPath string
}

type BundleInstallation struct {
	Version      string
	InstallPath  string
	CurrentPath  string
	TetraPath    string
	TetragonPath string
}

func VerifyBundle(cfg BundleConfig) (BundleVerification, error) {
	if strings.TrimSpace(cfg.BundleDir) == "" {
		return BundleVerification{}, fmt.Errorf("tetragon bundle_dir is required")
	}
	manifestPath := filepath.Join(cfg.BundleDir, "manifest.json")
	data, err := os.ReadFile(manifestPath)
	if err != nil {
		return BundleVerification{}, fmt.Errorf("read tetragon bundle manifest: %w", err)
	}
	var manifest BundleManifest
	if err := json.Unmarshal(data, &manifest); err != nil {
		return BundleVerification{}, fmt.Errorf("decode tetragon bundle manifest: %w", err)
	}
	if manifest.Version == "" {
		return BundleVerification{}, fmt.Errorf("tetragon bundle manifest version is required")
	}
	tetragonPath := firstNonEmpty(cfg.TetragonPath, filepath.Join(cfg.BundleDir, "bin", "tetragon"))
	tetraPath := firstNonEmpty(cfg.TetraPath, filepath.Join(cfg.BundleDir, "bin", "tetra"))
	if err := verifyManifestFile(cfg.BundleDir, manifest, "bin/tetragon", tetragonPath); err != nil {
		return BundleVerification{}, err
	}
	if err := verifyManifestFile(cfg.BundleDir, manifest, "bin/tetra", tetraPath); err != nil {
		return BundleVerification{}, err
	}
	return BundleVerification{
		Version:      manifest.Version,
		TetraPath:    tetraPath,
		TetragonPath: tetragonPath,
	}, nil
}

func verifyManifestFile(bundleDir string, manifest BundleManifest, relPath, actualPath string) error {
	file, ok := manifest.Files[relPath]
	if !ok {
		return fmt.Errorf("tetragon bundle manifest missing %s", relPath)
	}
	want := strings.ToLower(strings.TrimSpace(file.SHA256))
	if want == "" {
		return fmt.Errorf("tetragon bundle manifest missing sha256 for %s", relPath)
	}
	if !filepath.IsAbs(actualPath) {
		actualPath = filepath.Join(bundleDir, actualPath)
	}
	got, err := sha256File(actualPath)
	if err != nil {
		return fmt.Errorf("verify tetragon bundle file %s: %w", relPath, err)
	}
	if got != want {
		return fmt.Errorf("verify tetragon bundle file %s: checksum mismatch got=%s want=%s", relPath, got, want)
	}
	return nil
}

func InstallBundle(cfg BundleConfig) (BundleInstallation, error) {
	if strings.TrimSpace(cfg.InstallDir) == "" {
		return BundleInstallation{}, fmt.Errorf("tetragon install_dir is required")
	}
	verified, err := VerifyBundle(cfg)
	if err != nil {
		return BundleInstallation{}, err
	}
	installPath := filepath.Join(cfg.InstallDir, "tetragon", verified.Version)
	if err := copyBundle(cfg.BundleDir, installPath); err != nil {
		return BundleInstallation{}, err
	}
	currentPath := filepath.Join(cfg.InstallDir, "tetragon", "current")
	if err := pointCurrent(currentPath, installPath); err != nil {
		return BundleInstallation{}, err
	}
	return BundleInstallation{
		Version:      verified.Version,
		InstallPath:  installPath,
		CurrentPath:  currentPath,
		TetraPath:    filepath.Join(currentPath, "bin", "tetra"),
		TetragonPath: filepath.Join(currentPath, "bin", "tetragon"),
	}, nil
}

func copyBundle(src, dst string) error {
	if err := os.MkdirAll(dst, 0o755); err != nil {
		return err
	}
	return filepath.WalkDir(src, func(path string, entry os.DirEntry, walkErr error) error {
		if walkErr != nil {
			return walkErr
		}
		rel, err := filepath.Rel(src, path)
		if err != nil {
			return err
		}
		if rel == "." {
			return nil
		}
		target := filepath.Join(dst, rel)
		info, err := entry.Info()
		if err != nil {
			return err
		}
		if entry.IsDir() {
			return os.MkdirAll(target, info.Mode().Perm())
		}
		if entry.Type()&os.ModeSymlink != 0 {
			linkTarget, err := os.Readlink(path)
			if err != nil {
				return err
			}
			_ = os.Remove(target)
			return os.Symlink(linkTarget, target)
		}
		return copyRegularFile(path, target, info.Mode().Perm())
	})
}

func copyRegularFile(src, dst string, mode os.FileMode) error {
	in, err := os.Open(src)
	if err != nil {
		return err
	}
	defer in.Close()
	tmp := dst + ".tmp"
	out, err := os.OpenFile(tmp, os.O_CREATE|os.O_TRUNC|os.O_WRONLY, mode)
	if err != nil {
		return err
	}
	if _, err := io.Copy(out, in); err != nil {
		_ = out.Close()
		_ = os.Remove(tmp)
		return err
	}
	if err := out.Close(); err != nil {
		_ = os.Remove(tmp)
		return err
	}
	if err := os.Chmod(tmp, mode); err != nil {
		_ = os.Remove(tmp)
		return err
	}
	return os.Rename(tmp, dst)
}

func pointCurrent(currentPath, installPath string) error {
	if err := os.MkdirAll(filepath.Dir(currentPath), 0o755); err != nil {
		return err
	}
	_ = os.Remove(currentPath)
	if runtime.GOOS == "windows" {
		return copyBundle(installPath, currentPath)
	}
	rel, err := filepath.Rel(filepath.Dir(currentPath), installPath)
	if err != nil {
		rel = installPath
	}
	return os.Symlink(rel, currentPath)
}

func sha256File(path string) (string, error) {
	f, err := os.Open(path)
	if err != nil {
		return "", err
	}
	defer f.Close()
	h := sha256.New()
	if _, err := io.Copy(h, f); err != nil {
		return "", err
	}
	return hex.EncodeToString(h.Sum(nil)), nil
}

func firstNonEmpty(values ...string) string {
	for _, value := range values {
		if strings.TrimSpace(value) != "" {
			return value
		}
	}
	return ""
}
