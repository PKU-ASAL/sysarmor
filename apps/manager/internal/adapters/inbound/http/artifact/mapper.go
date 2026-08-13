package artifact

import domainartifact "github.com/sysarmor/sysarmor-next-project/apps/manager/internal/domain/artifact"

func mapArtifact(value domainartifact.Artifact) artifactDTO {
	return artifactDTO{ID: value.ID, TenantID: value.TenantID.String(), Name: value.Name, Kind: value.Kind,
		Version: value.Version, OS: value.OS, Arch: value.Arch, SHA256: value.SHA256, SizeBytes: value.SizeBytes,
		Status: string(value.Status), StoragePath: value.StoragePath, CreatedAt: value.CreatedAt,
		UpdatedAt: value.UpdatedAt, CreatedBy: value.CreatedBy, Metadata: value.Metadata}
}

func mapArtifacts(values []domainartifact.Artifact) []artifactDTO {
	result := make([]artifactDTO, 0, len(values))
	for _, value := range values {
		result = append(result, mapArtifact(value))
	}
	return result
}

func mapChannel(value domainartifact.Channel) channelDTO {
	return channelDTO{TenantID: value.TenantID.String(), Name: value.Name, ArtifactID: value.ArtifactID,
		CreatedAt: value.CreatedAt, UpdatedAt: value.UpdatedAt, CreatedBy: value.CreatedBy}
}

func mapChannels(values []domainartifact.Channel) []channelDTO {
	result := make([]channelDTO, 0, len(values))
	for _, value := range values {
		result = append(result, mapChannel(value))
	}
	return result
}
