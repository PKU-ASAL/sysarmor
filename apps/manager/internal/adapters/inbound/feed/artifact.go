package feed

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"net/http"
	"os"
	"strings"
	"time"

	managerapp "github.com/sysarmor/sysarmor-next-project/apps/manager/internal/application/manager"
	artifactapp "github.com/sysarmor/sysarmor-next-project/apps/manager/internal/application/manager/artifact"
	domainartifact "github.com/sysarmor/sysarmor-next-project/apps/manager/internal/domain/artifact"
	"github.com/sysarmor/sysarmor-next-project/apps/manager/internal/domain/tenant"
)

const (
	artifactFeedSchema             = "sysarmor.artifact.feed/v1"
	artifactDownloadURLMetadataKey = "download_url"
	packageIndexSource             = "package-index"
)

type ArtifactService interface {
	Register(context.Context, managerapp.RequestContext, artifactapp.RegisterCommand) (domainartifact.Artifact, error)
	SetChannel(context.Context, managerapp.RequestContext, artifactapp.SetChannelCommand) (domainartifact.Channel, error)
}

type HTTPClient interface {
	Do(*http.Request) (*http.Response, error)
}

type ArtifactSeeder struct {
	service ArtifactService
	client  HTTPClient
}

func NewArtifactSeeder(service ArtifactService, client HTTPClient) *ArtifactSeeder {
	if client == nil {
		client = http.DefaultClient
	}
	return &ArtifactSeeder{service: service, client: client}
}

func (seeder *ArtifactSeeder) SeedFromEnv(ctx context.Context) error {
	feedURL := strings.TrimSpace(os.Getenv("SYSARMOR_AGENT_PACKAGE_INDEX_URL"))
	if feedURL == "" {
		feedURL = strings.TrimSpace(os.Getenv("SYSARMOR_ARTIFACT_FEED_URL"))
	}
	return seeder.Seed(ctx, feedURL)
}

func (seeder *ArtifactSeeder) Seed(ctx context.Context, feedURL string) error {
	feedURL = strings.TrimSpace(feedURL)
	if feedURL == "" {
		return nil
	}
	var lastErr error
	for {
		lastErr = seeder.seedOnce(ctx, feedURL)
		if lastErr == nil || !strings.Contains(lastErr.Error(), "fetch artifact feed") {
			return lastErr
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

func (seeder *ArtifactSeeder) seedOnce(ctx context.Context, feedURL string) error {
	request, err := http.NewRequestWithContext(ctx, http.MethodGet, feedURL, nil)
	if err != nil {
		return fmt.Errorf("create artifact feed request: %w", err)
	}
	response, err := seeder.client.Do(request)
	if err != nil {
		return fmt.Errorf("fetch artifact feed: %w", err)
	}
	defer response.Body.Close()
	if response.StatusCode != http.StatusOK {
		return fmt.Errorf("fetch artifact feed: status %d", response.StatusCode)
	}
	var feed artifactFeed
	if err := json.NewDecoder(response.Body).Decode(&feed); err != nil {
		return fmt.Errorf("decode artifact feed: %w", err)
	}
	return seeder.apply(ctx, feed)
}

func (seeder *ArtifactSeeder) SeedData(ctx context.Context, data []byte) error {
	var feed artifactFeed
	if err := json.NewDecoder(bytes.NewReader(data)).Decode(&feed); err != nil {
		return fmt.Errorf("decode artifact feed: %w", err)
	}
	return seeder.apply(ctx, feed)
}

func (seeder *ArtifactSeeder) apply(ctx context.Context, feed artifactFeed) error {
	if seeder == nil || seeder.service == nil {
		return fmt.Errorf("artifact feed service is required")
	}
	if feed.SchemaVersion != artifactFeedSchema {
		return fmt.Errorf("unsupported artifact feed schema %q", feed.SchemaVersion)
	}
	for _, item := range feed.Artifacts {
		if err := seeder.applyItem(ctx, item); err != nil {
			return err
		}
	}
	return nil
}

func (seeder *ArtifactSeeder) applyItem(ctx context.Context, item artifactFeedItem) error {
	requestContext, err := feedRequestContext(item.TenantID)
	if err != nil {
		return fmt.Errorf("seed artifact %q tenant_id: %w", item.Name, err)
	}
	command, err := item.registerCommand(requestContext.Actor.TenantID)
	if err != nil {
		return err
	}
	artifact, err := seeder.service.Register(ctx, requestContext, command)
	if err != nil {
		return fmt.Errorf("seed artifact %q: %w", item.Name, err)
	}
	for _, name := range item.Channels {
		name = strings.TrimSpace(name)
		if name == "" {
			continue
		}
		if _, err := seeder.service.SetChannel(ctx, requestContext,
			artifactapp.SetChannelCommand{Name: name, ArtifactID: artifact.ID}); err != nil {
			return fmt.Errorf("seed channel %q: %w", name, err)
		}
	}
	return nil
}

func feedRequestContext(rawTenantID string) (managerapp.RequestContext, error) {
	tenantID, err := tenant.NewID(strings.TrimSpace(rawTenantID))
	if err != nil {
		return managerapp.RequestContext{}, err
	}
	return managerapp.RequestContext{Actor: tenant.Actor{Subject: packageIndexSource, TenantID: tenantID,
		Roles: tenant.NewRoleSet(tenant.RoleOperator)}}, nil
}

type artifactFeed struct {
	SchemaVersion string             `json:"schema_version"`
	Artifacts     []artifactFeedItem `json:"artifacts"`
}

type artifactFeedItem struct {
	ID          string   `json:"artifact_id"`
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

func (item artifactFeedItem) registerCommand(tenantID tenant.ID) (artifactapp.RegisterCommand, error) {
	downloadURL := strings.TrimSpace(item.DownloadURL)
	if downloadURL == "" {
		return artifactapp.RegisterCommand{}, fmt.Errorf("seed artifact %q: download_url is required", item.Name)
	}
	status := domainartifact.Status(strings.TrimSpace(item.Status))
	if status == "" {
		status = domainartifact.StatusActive
	}
	id := strings.TrimSpace(item.ID)
	if id == "" {
		id = strings.Join([]string{"release", item.Name, item.OS, item.Arch, item.Version}, "-")
	}
	return artifactapp.RegisterCommand{Value: domainartifact.Artifact{ID: id, TenantID: tenantID,
		Name: item.Name, Kind: item.Kind, Version: item.Version, OS: item.OS, Arch: item.Arch,
		SHA256: item.SHA256, SizeBytes: item.SizeBytes, Status: status, CreatedBy: packageIndexSource,
		Metadata: map[string]string{artifactDownloadURLMetadataKey: downloadURL, "source": packageIndexSource}}}, nil
}
