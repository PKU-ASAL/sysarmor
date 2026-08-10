package archive

import (
	"archive/tar"
	"bytes"
	"compress/gzip"
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"io"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/sysarmor/sysarmor-next-project/apps/manager/internal/adapters/outbound/archive/distribution"
	"github.com/sysarmor/sysarmor-next-project/apps/manager/internal/domain/failure"
	"github.com/sysarmor/sysarmor-next-project/apps/manager/internal/domain/tenant"
	"github.com/sysarmor/sysarmor-next-project/apps/manager/internal/ports"
)

func TestArtifactArchiveStoresContentInsideRoot(t *testing.T) {
	root := t.TempDir()
	archive := NewArtifactArchive(root, nil)
	content := []byte("artifact-content")
	stored, err := archive.Store(context.Background(), tenant.ID("tenant/a"), ports.ArtifactArchiveInput{
		Name: "bundle/name", Kind: "bundle", Version: "1.0.0", Filename: "../artifact.bin",
		Content: bytes.NewReader(content),
	})
	if err != nil {
		t.Fatal(err)
	}
	wantHash := sha256.Sum256(content)
	if stored.ID == "" || stored.SHA256 != hex.EncodeToString(wantHash[:]) || stored.SizeBytes != int64(len(content)) {
		t.Fatalf("stored=%+v", stored)
	}
	relative, err := filepath.Rel(root, stored.StoragePath)
	if err != nil || strings.HasPrefix(relative, "..") || filepath.Base(stored.StoragePath) != "artifact.bin" {
		t.Fatalf("path=%q relative=%q error=%v", stored.StoragePath, relative, err)
	}
	opened, err := archive.Open(context.Background(), stored.StoragePath)
	if err != nil {
		t.Fatal(err)
	}
	gotContent, err := io.ReadAll(opened.Content)
	if closeErr := opened.Content.Close(); err == nil {
		err = closeErr
	}
	if err != nil || !bytes.Equal(gotContent, content) || opened.Name != "artifact.bin" {
		t.Fatalf("content=%q opened=%+v error=%v", gotContent, opened, err)
	}
	if err := archive.Remove(context.Background(), stored.StoragePath); err != nil {
		t.Fatal(err)
	}
	if _, err := os.Stat(stored.StoragePath); !os.IsNotExist(err) {
		t.Fatalf("removed artifact stat error=%v", err)
	}
}

func TestArtifactArchiveRejectsOpenOutsideRoot(t *testing.T) {
	archive := NewArtifactArchive(t.TempDir(), nil)
	if _, err := archive.Open(context.Background(), "/etc/passwd"); err == nil {
		t.Fatal("Open() accepted path outside archive root")
	}
}

func TestArtifactArchiveRejectsAgentManifestMismatchAndRemovesFile(t *testing.T) {
	root := t.TempDir()
	archive := NewArtifactArchive(root, nil)
	_, err := archive.Store(context.Background(), tenant.ID("tenant-a"), ports.ArtifactArchiveInput{
		Name: "different-name", Kind: "agent", Version: "1.0.0", Filename: "agent.tar.gz",
		OS: "linux", Arch: "amd64", Content: bytes.NewReader(agentArchive(t)),
	})
	if failure.KindOf(err) != failure.InvalidArgument || !strings.Contains(err.Error(), "does not match distribution manifest") {
		t.Fatalf("error=%v", err)
	}
	regularFiles := 0
	if walkErr := filepath.Walk(root, func(_ string, info os.FileInfo, walkErr error) error {
		if walkErr == nil && info.Mode().IsRegular() {
			regularFiles++
		}
		return walkErr
	}); walkErr != nil || regularFiles != 0 {
		t.Fatalf("regular files=%d walk error=%v", regularFiles, walkErr)
	}
}

func agentArchive(t *testing.T) []byte {
	t.Helper()
	payload := []byte("hello")
	digest := sha256.Sum256(payload)
	manifest := distribution.Manifest{SchemaVersion: distribution.SchemaVersion, Name: "sysarmor-agent",
		Version: "1.0.0", OS: "linux", Arch: "amd64", Entrypoint: "install.sh",
		SystemdUnit: "sysarmor-agent.service", Files: []distribution.FileSpec{{
			Path: "install.sh", SHA256: hex.EncodeToString(digest[:]),
		}}}
	rawManifest, err := json.Marshal(manifest)
	if err != nil {
		t.Fatal(err)
	}
	var buffer bytes.Buffer
	gzipWriter := gzip.NewWriter(&buffer)
	tarWriter := tar.NewWriter(gzipWriter)
	writeTarEntry(t, tarWriter, "manifest.json", rawManifest)
	writeTarEntry(t, tarWriter, "install.sh", payload)
	if err := tarWriter.Close(); err != nil {
		t.Fatal(err)
	}
	if err := gzipWriter.Close(); err != nil {
		t.Fatal(err)
	}
	return buffer.Bytes()
}

func writeTarEntry(t *testing.T, writer *tar.Writer, name string, content []byte) {
	t.Helper()
	if err := writer.WriteHeader(&tar.Header{Name: name, Typeflag: tar.TypeReg, Mode: 0o644, Size: int64(len(content))}); err != nil {
		t.Fatal(err)
	}
	if _, err := writer.Write(content); err != nil {
		t.Fatal(err)
	}
}
