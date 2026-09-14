package distribution

import (
	"archive/tar"
	"compress/gzip"
	"crypto"
	"crypto/rand"
	"crypto/rsa"
	"crypto/sha256"
	"crypto/x509"
	"encoding/hex"
	"encoding/json"
	"encoding/pem"
	"fmt"
	"io"
	"os"
	"path"
	"strings"
)

const SchemaVersion = "sysarmor.agent.distribution/v1"

const (
	maxArchiveFileBytes     = 512 * 1024 * 1024
	maxArchiveTotalBytes    = 1024 * 1024 * 1024
	maxArchiveEntries       = 10_000
	maxArchiveMetadataBytes = 4 * 1024 * 1024
)

type inspectLimits struct {
	MaxFileBytes     int64
	MaxTotalBytes    int64
	MaxEntries       int
	MaxMetadataBytes int64
}

type archiveIndex struct {
	entries  map[string]byte
	digests  map[string]string
	metadata map[string][]byte
}

type Manifest struct {
	SchemaVersion string            `json:"schema_version"`
	Name          string            `json:"name"`
	Version       string            `json:"version"`
	OS            string            `json:"os"`
	Arch          string            `json:"arch"`
	Entrypoint    string            `json:"entrypoint"`
	SystemdUnit   string            `json:"systemd_unit"`
	Install       InstallSpec       `json:"install"`
	Sensors       []SensorSpec      `json:"sensors,omitempty"`
	Files         []FileSpec        `json:"files"`
	Metadata      map[string]string `json:"metadata,omitempty"`
}

type InstallSpec struct {
	AgentHome     string `json:"agent_home"`
	ConfigPath    string `json:"config_path"`
	PolicyDir     string `json:"policy_dir"`
	RuntimeSocket string `json:"runtime_socket"`
}

type SensorSpec struct {
	Name       string `json:"name"`
	Backend    string `json:"backend"`
	BundleDir  string `json:"bundle_dir"`
	InstallDir string `json:"install_dir"`
}

type FileSpec struct {
	Path   string `json:"path"`
	Mode   string `json:"mode,omitempty"`
	SHA256 string `json:"sha256"`
}

type InspectResult struct {
	Manifest Manifest
	Signed   bool
}

func InspectTarGz(archivePath string, publicKeyPEM []byte) (InspectResult, error) {
	return inspectTarGzWithLimits(archivePath, publicKeyPEM, inspectLimits{})
}

func inspectTarGzWithLimits(archivePath string, publicKeyPEM []byte, limits inspectLimits) (InspectResult, error) {
	limits = normalizeInspectLimits(limits)
	f, err := os.Open(archivePath)
	if err != nil {
		return InspectResult{}, err
	}
	defer f.Close()
	gz, err := gzip.NewReader(f)
	if err != nil {
		return InspectResult{}, fmt.Errorf("open gzip: %w", err)
	}
	defer gz.Close()
	index, err := readArchiveIndex(tar.NewReader(gz), limits)
	if err != nil {
		return InspectResult{}, err
	}
	return inspectArchiveIndex(index, publicKeyPEM)
}

func normalizeInspectLimits(limits inspectLimits) inspectLimits {
	if limits.MaxFileBytes <= 0 {
		limits.MaxFileBytes = maxArchiveFileBytes
	}
	if limits.MaxTotalBytes <= 0 {
		limits.MaxTotalBytes = maxArchiveTotalBytes
	}
	if limits.MaxEntries <= 0 {
		limits.MaxEntries = maxArchiveEntries
	}
	if limits.MaxMetadataBytes <= 0 {
		limits.MaxMetadataBytes = maxArchiveMetadataBytes
	}
	return limits
}

func readArchiveIndex(tr *tar.Reader, limits inspectLimits) (archiveIndex, error) {
	index := archiveIndex{entries: map[string]byte{}, digests: map[string]string{}, metadata: map[string][]byte{}}
	var totalBytes int64
	entryCount := 0
	for {
		hdr, err := tr.Next()
		if err == io.EOF {
			return index, nil
		}
		if err != nil {
			return archiveIndex{}, fmt.Errorf("read tar: %w", err)
		}
		if hdr.Typeflag == tar.TypeDir && (hdr.Name == "." || hdr.Name == "./") {
			continue
		}
		entryCount++
		if entryCount > limits.MaxEntries {
			return archiveIndex{}, fmt.Errorf("archive entry limit exceeded: %d > %d", entryCount, limits.MaxEntries)
		}
		clean, err := cleanArchivePath(hdr.Name)
		if err != nil {
			return archiveIndex{}, err
		}
		if _, exists := index.entries[clean]; exists {
			return archiveIndex{}, fmt.Errorf("duplicate archive entry: %s", clean)
		}
		index.entries[clean] = hdr.Typeflag
		if hdr.Typeflag == tar.TypeDir {
			continue
		}
		if hdr.Typeflag != tar.TypeReg {
			return archiveIndex{}, fmt.Errorf("unsupported archive entry %s type %c", clean, hdr.Typeflag)
		}
		if hdr.Size > limits.MaxFileBytes {
			return archiveIndex{}, fmt.Errorf("%s exceeds archive file size limit: %d > %d", clean, hdr.Size, limits.MaxFileBytes)
		}
		if hdr.Size > limits.MaxTotalBytes-totalBytes {
			return archiveIndex{}, fmt.Errorf("archive total uncompressed size limit exceeded: %d > %d", totalBytes+hdr.Size, limits.MaxTotalBytes)
		}
		totalBytes += hdr.Size
		if err := readIndexedFile(tr, hdr, clean, limits, &index); err != nil {
			return archiveIndex{}, err
		}
	}
}

func readIndexedFile(tr *tar.Reader, hdr *tar.Header, clean string, limits inspectLimits, index *archiveIndex) error {
	hash := sha256.New()
	if clean == "manifest.json" || clean == "manifest.sig" {
		if hdr.Size > limits.MaxMetadataBytes {
			return fmt.Errorf("%s exceeds archive metadata size limit: %d > %d", clean, hdr.Size, limits.MaxMetadataBytes)
		}
		data, err := io.ReadAll(io.TeeReader(tr, hash))
		if err != nil {
			return fmt.Errorf("read %s: %w", hdr.Name, err)
		}
		index.metadata[clean] = data
	} else if _, err := io.Copy(hash, tr); err != nil {
		return fmt.Errorf("read %s: %w", hdr.Name, err)
	}
	index.digests[clean] = hex.EncodeToString(hash.Sum(nil))
	return nil
}

func inspectArchiveIndex(index archiveIndex, publicKeyPEM []byte) (InspectResult, error) {
	raw, ok := index.metadata["manifest.json"]
	if !ok {
		return InspectResult{}, fmt.Errorf("manifest.json is required")
	}
	var manifest Manifest
	if err := json.Unmarshal(raw, &manifest); err != nil {
		return InspectResult{}, fmt.Errorf("decode manifest: %w", err)
	}
	if err := Validate(manifest); err != nil {
		return InspectResult{}, err
	}
	sig, signed := index.metadata["manifest.sig"]
	if len(publicKeyPEM) > 0 {
		if !signed {
			return InspectResult{}, fmt.Errorf("manifest.sig is required")
		}
		if err := Verify(raw, sig, publicKeyPEM); err != nil {
			return InspectResult{}, err
		}
	}
	for _, spec := range manifest.Files {
		clean, err := cleanArchivePath(spec.Path)
		if err != nil {
			return InspectResult{}, err
		}
		digest, ok := index.digests[clean]
		if !ok {
			return InspectResult{}, fmt.Errorf("manifest file missing: %s", spec.Path)
		}
		if !strings.EqualFold(digest, spec.SHA256) {
			return InspectResult{}, fmt.Errorf("manifest file sha256 mismatch: %s", spec.Path)
		}
	}
	allowed := map[string]bool{"manifest.json": true}
	if signed {
		allowed["manifest.sig"] = true
	}
	for _, spec := range manifest.Files {
		clean, _ := cleanArchivePath(spec.Path)
		allowed[clean] = true
		for dir := path.Dir(clean); dir != "." && dir != "/"; dir = path.Dir(dir) {
			allowed[dir] = true
		}
	}
	for entry := range index.entries {
		if !allowed[entry] {
			return InspectResult{}, fmt.Errorf("unexpected archive entry: %s", entry)
		}
	}
	return InspectResult{Manifest: manifest, Signed: signed}, nil
}

func Validate(m Manifest) error {
	if m.SchemaVersion != SchemaVersion {
		return fmt.Errorf("unsupported manifest schema_version %q", m.SchemaVersion)
	}
	if strings.TrimSpace(m.Name) == "" || strings.TrimSpace(m.Version) == "" || strings.TrimSpace(m.OS) == "" || strings.TrimSpace(m.Arch) == "" {
		return fmt.Errorf("manifest name, version, os, and arch are required")
	}
	if strings.TrimSpace(m.Entrypoint) == "" || strings.TrimSpace(m.SystemdUnit) == "" {
		return fmt.Errorf("manifest entrypoint and systemd_unit are required")
	}
	if len(m.Files) == 0 {
		return fmt.Errorf("manifest files are required")
	}
	for _, p := range []string{m.Entrypoint, m.SystemdUnit} {
		if _, err := cleanArchivePath(p); err != nil {
			return err
		}
	}
	for _, f := range m.Files {
		if _, err := cleanArchivePath(f.Path); err != nil {
			return err
		}
		if len(f.SHA256) != 64 {
			return fmt.Errorf("invalid sha256 for %s", f.Path)
		}
	}
	for _, sensor := range m.Sensors {
		if strings.TrimSpace(sensor.Name) == "" || strings.TrimSpace(sensor.Backend) == "" {
			return fmt.Errorf("sensor name and backend are required")
		}
		if _, err := cleanArchivePath(sensor.BundleDir); err != nil {
			return err
		}
		if strings.TrimSpace(sensor.InstallDir) == "" {
			return fmt.Errorf("sensor install_dir is required")
		}
	}
	return nil
}

func Verify(data, signature, publicKeyPEM []byte) error {
	block, _ := pem.Decode(publicKeyPEM)
	if block == nil {
		return fmt.Errorf("decode artifact public key")
	}
	parsed, err := x509.ParsePKIXPublicKey(block.Bytes)
	if err != nil {
		return fmt.Errorf("parse artifact public key: %w", err)
	}
	pub, ok := parsed.(*rsa.PublicKey)
	if !ok {
		return fmt.Errorf("artifact public key must be RSA")
	}
	sum := sha256.Sum256(data)
	if err := rsa.VerifyPKCS1v15(pub, crypto.SHA256, sum[:], signature); err != nil {
		return fmt.Errorf("verify manifest signature: %w", err)
	}
	return nil
}

func Sign(data []byte, privateKeyPEM []byte) ([]byte, error) {
	block, _ := pem.Decode(privateKeyPEM)
	if block == nil {
		return nil, fmt.Errorf("decode artifact private key")
	}
	key, err := x509.ParsePKCS1PrivateKey(block.Bytes)
	if err != nil {
		parsed, parseErr := x509.ParsePKCS8PrivateKey(block.Bytes)
		if parseErr != nil {
			return nil, fmt.Errorf("parse artifact private key: %w", err)
		}
		var ok bool
		key, ok = parsed.(*rsa.PrivateKey)
		if !ok {
			return nil, fmt.Errorf("artifact private key must be RSA")
		}
	}
	sum := sha256.Sum256(data)
	return rsa.SignPKCS1v15(rand.Reader, key, crypto.SHA256, sum[:])
}

func cleanArchivePath(p string) (string, error) {
	p = strings.TrimSpace(strings.TrimPrefix(p, "./"))
	if p == "" || strings.HasPrefix(p, "/") {
		return "", fmt.Errorf("invalid archive path %q", p)
	}
	clean := path.Clean(p)
	if clean == "." || strings.HasPrefix(clean, "../") || clean == ".." {
		return "", fmt.Errorf("invalid archive path %q", p)
	}
	return clean, nil
}
