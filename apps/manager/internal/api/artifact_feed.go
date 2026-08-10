package managerapi

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"net/http"
	"net/url"
	"os"
	"path"
	"strings"
	"time"

	"github.com/sysarmor/sysarmor-next-project/apps/manager/internal/store"
)

const artifactDownloadURLMetadataKey = "download_url"
const packageIndexSource = "package-index"

type artifactFeed struct {
	SchemaVersion string             `json:"schema_version"`
	Artifacts     []artifactFeedItem `json:"artifacts"`
}

type artifactFeedItem struct {
	ArtifactID  string   `json:"artifact_id"`
	TenantID    string   `json:"tenant_id"`
	Name        string   `json:"name"`
	Kind        string   `json:"kind"`
	Version     string   `json:"version"`
	OS          string   `json:"os"`
	Arch        string   `json:"arch"`
	SHA256      string   `json:"sha256"`
	SizeBytes   int64    `json:"size_bytes"`
	Status      string   `json:"status"`
	DownloadURL string   `json:"download_url"`
	Channels    []string `json:"channels"`
}

func (s *Server) SeedArtifactFeedFromEnv(ctx context.Context) error {
	feedURL := strings.TrimSpace(os.Getenv("SYSARMOR_AGENT_PACKAGE_INDEX_URL"))
	if feedURL == "" {
		feedURL = strings.TrimSpace(os.Getenv("SYSARMOR_ARTIFACT_FEED_URL"))
	}
	if feedURL == "" {
		return nil
	}
	return s.SeedArtifactFeed(ctx, feedURL)
}

func (s *Server) SeedArtifactFeed(ctx context.Context, feedURL string) error {
	feedURL = strings.TrimSpace(feedURL)
	if feedURL == "" {
		return nil
	}
	var lastErr error
	for {
		if err := s.seedArtifactFeedOnce(ctx, feedURL); err != nil {
			lastErr = err
			if !isRetryableArtifactFeedError(err) {
				return err
			}
		} else {
			return nil
		}
		timer := time.NewTimer(500 * time.Millisecond)
		select {
		case <-ctx.Done():
			timer.Stop()
			return lastErr
		case <-timer.C:
		}
	}
}

func isRetryableArtifactFeedError(err error) bool {
	return err != nil && strings.Contains(err.Error(), "fetch artifact feed")
}

func (s *Server) seedArtifactFeedOnce(ctx context.Context, feedURL string) error {
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, feedURL, nil)
	if err != nil {
		return fmt.Errorf("create artifact feed request: %w", err)
	}
	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		return fmt.Errorf("fetch artifact feed: %w", err)
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		return fmt.Errorf("fetch artifact feed: status %d", resp.StatusCode)
	}
	return s.seedArtifactFeedDecoder(json.NewDecoder(resp.Body))
}

func (s *Server) SeedArtifactFeedData(data []byte) error {
	return s.seedArtifactFeedDecoder(json.NewDecoder(bytes.NewReader(data)))
}

func (s *Server) seedArtifactFeedDecoder(decoder *json.Decoder) error {
	var feed artifactFeed
	if err := decoder.Decode(&feed); err != nil {
		return fmt.Errorf("decode artifact feed: %w", err)
	}
	if feed.SchemaVersion != "sysarmor.artifact.feed/v1" {
		return fmt.Errorf("unsupported artifact feed schema %q", feed.SchemaVersion)
	}
	now := time.Now().UTC()
	for _, item := range feed.Artifacts {
		artifact, err := item.artifact(now)
		if err != nil {
			return err
		}
		artifact = s.store.UpsertArtifact(artifact)
		if artifact.ArtifactID == "" {
			return fmt.Errorf("seed artifact %q: upsert failed", item.Name)
		}
		for _, channelName := range item.Channels {
			channelName = strings.TrimSpace(channelName)
			if channelName == "" {
				continue
			}
			channel := s.store.UpsertChannel(store.ArtifactChannel{
				TenantID:   artifact.TenantID,
				Channel:    channelName,
				ArtifactID: artifact.ArtifactID,
				UpdatedAt:  now,
				CreatedBy:  packageIndexSource,
			})
			if channel.Channel == "" {
				return fmt.Errorf("seed channel %q: upsert failed", channelName)
			}
		}
	}
	if err := s.store.Save(); err != nil {
		return fmt.Errorf("save artifact feed: %w", err)
	}
	return nil
}

func (item artifactFeedItem) artifact(now time.Time) (store.Artifact, error) {
	tenantID := strings.TrimSpace(item.TenantID)
	if tenantID == "" {
		tenantID = "default"
	}
	status := strings.TrimSpace(item.Status)
	if status == "" {
		status = "active"
	}
	artifactID := strings.TrimSpace(item.ArtifactID)
	if artifactID == "" {
		artifactID = strings.Join([]string{"release", item.Name, item.OS, item.Arch, item.Version}, "-")
	}
	downloadURL := strings.TrimSpace(item.DownloadURL)
	if downloadURL == "" {
		return store.Artifact{}, fmt.Errorf("seed artifact %q: download_url is required", item.Name)
	}
	metadata := map[string]string{
		artifactDownloadURLMetadataKey: downloadURL,
		"source":                       packageIndexSource,
	}
	return store.Artifact{
		ArtifactID: artifactID,
		TenantID:   tenantID,
		Name:       item.Name,
		Kind:       item.Kind,
		Version:    item.Version,
		OS:         item.OS,
		Arch:       item.Arch,
		SHA256:     item.SHA256,
		SizeBytes:  item.SizeBytes,
		Status:     status,
		CreatedAt:  now,
		UpdatedAt:  now,
		CreatedBy:  packageIndexSource,
		Metadata:   metadata,
	}, nil
}

func artifactInstallURL(r *http.Request, artifact store.Artifact) string {
	return artifactInstallURLForProfile(r, artifact, "")
}

func artifactInstallURLForProfile(r *http.Request, artifact store.Artifact, profile string) string {
	if artifact.Metadata != nil {
		if url := strings.TrimSpace(artifact.Metadata[artifactDownloadURLMetadataKey]); url != "" {
			if strings.TrimSpace(profile) == "linux-container" {
				return url
			}
			return rewritePackageDownloadURL(url)
		}
	}
	return artifactDownloadURL(r, artifact.ArtifactID)
}

func rewritePackageDownloadURL(downloadURL string) string {
	base := strings.TrimSpace(os.Getenv("SYSARMOR_AGENT_PACKAGE_DOWNLOAD_BASE_URL"))
	if base == "" {
		return downloadURL
	}
	parsed, err := url.Parse(downloadURL)
	if err != nil || parsed.Path == "" {
		return downloadURL
	}
	base = strings.TrimRight(base, "/")
	return base + "/" + path.Base(parsed.Path)
}
