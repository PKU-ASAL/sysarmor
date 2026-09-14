package content

import (
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"strings"
)

func OpenLayered(opts Options) (*Store, error) {
	defaults, manifest, err := loadDefaultLayer(strings.TrimSpace(opts.DefaultDir), opts)
	if err != nil {
		return nil, err
	}
	users, err := NewStoreWithOptions(Options{Dir: opts.Dir, TrustedKeys: opts.TrustedKeys})
	if err != nil {
		return nil, fmt.Errorf("load user content: %w", err)
	}
	for ref, record := range defaults {
		if _, exists := users.records[ref]; exists {
			return nil, fmt.Errorf("content ref conflict between default and user layers: %s", ref)
		}
		users.records[ref] = record
		users.defaultRefs[ref] = true
	}
	users.manifestVersion = manifest.Version
	return users, nil
}

func loadDefaultLayer(dir string, opts Options) (map[string]Record, Manifest, error) {
	if dir == "" {
		return nil, Manifest{}, fmt.Errorf("default content directory is required")
	}
	data, err := os.ReadFile(filepath.Join(dir, "content-manifest.json"))
	if err != nil {
		return nil, Manifest{}, fmt.Errorf("read default content manifest: %w", err)
	}
	var manifest Manifest
	if err := json.Unmarshal(data, &manifest); err != nil {
		return nil, Manifest{}, fmt.Errorf("decode default content manifest: %w", err)
	}
	if err := validateManifestFiles(dir, manifest); err != nil {
		return nil, Manifest{}, err
	}
	records := make(map[string]Record, len(manifest.Entries))
	validator := &Store{trustedKeys: opts.TrustedKeys}
	for _, entry := range manifest.Entries {
		record, err := loadManifestEntry(dir, entry, validator)
		if err != nil {
			return nil, Manifest{}, err
		}
		if _, exists := records[record.Ref]; exists {
			return nil, Manifest{}, fmt.Errorf("duplicate default content ref %s", record.Ref)
		}
		records[record.Ref] = record
	}
	return records, manifest, nil
}

func validateManifestFiles(dir string, manifest Manifest) error {
	listed := map[string]bool{"content-manifest.json": true}
	for _, entry := range manifest.Entries {
		if entry.File == "" || filepath.Base(entry.File) != entry.File {
			return fmt.Errorf("invalid default content file for %s", entry.Ref)
		}
		listed[entry.File] = true
	}
	entries, err := os.ReadDir(dir)
	if err != nil {
		return fmt.Errorf("read default content directory: %w", err)
	}
	for _, entry := range entries {
		if !entry.IsDir() && strings.HasSuffix(entry.Name(), ".json") && !listed[entry.Name()] {
			return fmt.Errorf("unlisted default content file %s", entry.Name())
		}
	}
	return nil
}

func loadManifestEntry(dir string, entry ManifestEntry, validator *Store) (Record, error) {
	data, err := os.ReadFile(filepath.Join(dir, filepath.Base(entry.File)))
	if err != nil {
		return Record{}, fmt.Errorf("load default content %s: %w", entry.Ref, err)
	}
	env, err := Parse(string(data))
	if err != nil {
		return Record{}, fmt.Errorf("parse default content %s: %w", entry.Ref, err)
	}
	if err := validator.Validate(env, false); err != nil {
		return Record{}, fmt.Errorf("validate default content %s: %w", entry.Ref, err)
	}
	record := Record{Ref: env.Metadata.ID, Kind: env.Kind, Version: env.Metadata.Version, Digest: signedDigest(env), Signed: true, Status: "loaded", RawJSON: string(data)}
	if record.Ref != entry.Ref || record.Kind != entry.Kind || record.Version != entry.Version || !strings.EqualFold(record.Digest, entry.Digest) {
		return Record{}, fmt.Errorf("default content manifest metadata mismatch for %s", entry.Ref)
	}
	if err := validateRecordPayload(record); err != nil {
		return Record{}, fmt.Errorf("parse default content %s: %w", entry.Ref, err)
	}
	return record, nil
}

func (s *Store) IsDefaultRef(ref string) bool {
	s.mu.RLock()
	defer s.mu.RUnlock()
	return s.defaultRefs[ref]
}

func (s *Store) DefaultManifestVersion() string {
	s.mu.RLock()
	defer s.mu.RUnlock()
	return s.manifestVersion
}
