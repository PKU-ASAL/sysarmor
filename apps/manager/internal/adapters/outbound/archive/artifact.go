package archive

import (
	"context"
	"crypto/rand"
	"crypto/sha256"
	"encoding/hex"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"time"

	"github.com/sysarmor/sysarmor-next-project/apps/manager/internal/adapters/outbound/archive/distribution"
	"github.com/sysarmor/sysarmor-next-project/apps/manager/internal/domain/failure"
	"github.com/sysarmor/sysarmor-next-project/apps/manager/internal/domain/tenant"
	"github.com/sysarmor/sysarmor-next-project/apps/manager/internal/ports"
)

type ArtifactArchive struct {
	root      string
	publicKey []byte
}

func NewArtifactArchive(root string, publicKey []byte) *ArtifactArchive {
	return &ArtifactArchive{root: strings.TrimSpace(root), publicKey: append([]byte(nil), publicKey...)}
}

func (archive *ArtifactArchive) Store(ctx context.Context, tenantID tenant.ID, input ports.ArtifactArchiveInput) (ports.ArchivedArtifact, error) {
	if archive == nil || archive.root == "" {
		return ports.ArchivedArtifact{}, failure.New(failure.Internal, "artifact archive root is required")
	}
	if tenantID.IsZero() || input.Content == nil {
		return ports.ArchivedArtifact{}, failure.New(failure.InvalidArgument, "artifact tenant and content are required")
	}
	if err := ctx.Err(); err != nil {
		return ports.ArchivedArtifact{}, err
	}
	stored, err := archive.write(tenantID, input)
	if err != nil {
		return ports.ArchivedArtifact{}, err
	}
	metadata, err := archive.inspect(input, stored.StoragePath)
	if err != nil {
		_ = os.Remove(stored.StoragePath)
		return ports.ArchivedArtifact{}, err
	}
	stored.Metadata = metadata
	return stored, nil
}

func (archive *ArtifactArchive) write(tenantID tenant.ID, input ports.ArtifactArchiveInput) (ports.ArchivedArtifact, error) {
	now := time.Now().UTC()
	id := "art-" + now.Format("20060102T150405Z") + "-" + randomSuffix()
	directory := filepath.Join(archive.root, safeSegment(tenantID.String()), safeSegment(input.Kind),
		safeSegment(input.Name), safeSegment(input.Version), safeSegment(id))
	if err := os.MkdirAll(directory, 0o755); err != nil {
		return ports.ArchivedArtifact{}, fmt.Errorf("create artifact directory: %w", err)
	}
	filename := safeFilename(input.Filename)
	if filename == "" {
		filename = "artifact.tar.gz"
	}
	return writeContent(directory, filename, id, input.Content)
}

func writeContent(directory, filename, id string, content io.Reader) (ports.ArchivedArtifact, error) {
	temporary, err := os.CreateTemp(directory, ".upload-*.tmp")
	if err != nil {
		return ports.ArchivedArtifact{}, fmt.Errorf("create artifact temporary file: %w", err)
	}
	temporaryPath := temporary.Name()
	hasher := sha256.New()
	size, copyErr := io.Copy(io.MultiWriter(temporary, hasher), content)
	closeErr := temporary.Close()
	if copyErr != nil || closeErr != nil {
		_ = os.Remove(temporaryPath)
		if copyErr != nil {
			return ports.ArchivedArtifact{}, fmt.Errorf("write artifact: %w", copyErr)
		}
		return ports.ArchivedArtifact{}, fmt.Errorf("close artifact: %w", closeErr)
	}
	finalPath := filepath.Join(directory, filename)
	if err := os.Rename(temporaryPath, finalPath); err != nil {
		_ = os.Remove(temporaryPath)
		return ports.ArchivedArtifact{}, fmt.Errorf("store artifact: %w", err)
	}
	return ports.ArchivedArtifact{ID: id, SHA256: hex.EncodeToString(hasher.Sum(nil)),
		SizeBytes: size, StoragePath: finalPath}, nil
}

func (archive *ArtifactArchive) inspect(input ports.ArtifactArchiveInput, path string) (map[string]string, error) {
	if strings.TrimSpace(input.Kind) != "agent" {
		return nil, nil
	}
	result, err := distribution.InspectTarGz(path, archive.publicKey)
	if err != nil {
		return nil, failure.New(failure.InvalidArgument, fmt.Sprintf("inspect agent distribution: %v", err))
	}
	if result.Manifest.Name != strings.TrimSpace(input.Name) || result.Manifest.Version != strings.TrimSpace(input.Version) ||
		(input.OS != "" && result.Manifest.OS != strings.TrimSpace(input.OS)) ||
		(input.Arch != "" && result.Manifest.Arch != strings.TrimSpace(input.Arch)) {
		return nil, failure.New(failure.InvalidArgument, "artifact form metadata does not match distribution manifest")
	}
	return map[string]string{"manifest_schema": result.Manifest.SchemaVersion,
		"manifest_entrypoint": result.Manifest.Entrypoint, "manifest_systemd_unit": result.Manifest.SystemdUnit,
		"manifest_signed": strconv.FormatBool(result.Signed)}, nil
}

func (archive *ArtifactArchive) Remove(_ context.Context, path string) error {
	if archive == nil || archive.root == "" || !withinRoot(archive.root, path) {
		return failure.New(failure.InvalidArgument, "artifact path escapes archive root")
	}
	if err := os.Remove(path); err != nil && !os.IsNotExist(err) {
		return fmt.Errorf("remove artifact: %w", err)
	}
	return nil
}

func (archive *ArtifactArchive) Open(ctx context.Context, path string) (ports.ArchivedContent, error) {
	if archive == nil || archive.root == "" || !withinRoot(archive.root, path) {
		return ports.ArchivedContent{}, failure.New(failure.InvalidArgument, "artifact path escapes archive root")
	}
	if err := ctx.Err(); err != nil {
		return ports.ArchivedContent{}, err
	}
	file, err := os.Open(path)
	if os.IsNotExist(err) {
		return ports.ArchivedContent{}, failure.New(failure.NotFound, "artifact content not found")
	}
	if err != nil {
		return ports.ArchivedContent{}, fmt.Errorf("open artifact: %w", err)
	}
	info, err := file.Stat()
	if err != nil {
		_ = file.Close()
		return ports.ArchivedContent{}, fmt.Errorf("stat artifact: %w", err)
	}
	return ports.ArchivedContent{Content: file, Name: info.Name(), Size: info.Size(), ModTime: info.ModTime()}, nil
}

func safeFilename(value string) string {
	value = filepath.Base(strings.TrimSpace(value))
	if value == "." || value == string(filepath.Separator) {
		return ""
	}
	return safeSegment(value)
}

func safeSegment(value string) string {
	value = strings.TrimSpace(value)
	if value == "" {
		return "_"
	}
	var builder strings.Builder
	for _, character := range value {
		if isSafeCharacter(character) {
			builder.WriteRune(character)
		} else {
			builder.WriteByte('_')
		}
	}
	return builder.String()
}

func isSafeCharacter(value rune) bool {
	return value >= 'a' && value <= 'z' || value >= 'A' && value <= 'Z' ||
		value >= '0' && value <= '9' || value == '.' || value == '-' || value == '_'
}

func withinRoot(root, path string) bool {
	absoluteRoot, err := filepath.Abs(root)
	if err != nil {
		return false
	}
	absolutePath, err := filepath.Abs(path)
	if err != nil {
		return false
	}
	relative, err := filepath.Rel(absoluteRoot, absolutePath)
	return err == nil && relative != ".." && !strings.HasPrefix(relative, ".."+string(filepath.Separator))
}

func randomSuffix() string {
	var value [6]byte
	if _, err := rand.Read(value[:]); err != nil {
		return strconv.FormatInt(time.Now().UnixNano(), 36)
	}
	return hex.EncodeToString(value[:])
}
