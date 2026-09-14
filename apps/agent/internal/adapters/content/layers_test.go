package content

import (
	"crypto/ed25519"
	"encoding/json"
	"os"
	"path/filepath"
	"testing"
)

func TestOpenLayeredLoadsManifestContent(t *testing.T) {
	defaultDir := t.TempDir()
	userDir := t.TempDir()
	pub, priv, err := ed25519.GenerateKey(nil)
	if err != nil {
		t.Fatal(err)
	}
	env := Envelope{
		APIVersion: "sysarmor.content/v1",
		Kind:       "contextset",
		Metadata:   Metadata{ID: "ctx:default", Version: "v1"},
		Spec:       json.RawMessage(`{"value_type":"string","values":["default"]}`),
	}
	writeDefaultContent(t, defaultDir, priv, "context.json", env)

	store, err := OpenLayered(Options{
		DefaultDir: defaultDir,
		Dir:        userDir,
		TrustedKeys: map[string]ed25519.PublicKey{
			"test": pub,
		},
	})
	if err != nil {
		t.Fatal(err)
	}
	if _, ok := store.Snapshot().ContextSets["ctx:default"]; !ok {
		t.Fatal("default context missing from snapshot")
	}
	if !store.IsDefaultRef("ctx:default") {
		t.Fatal("default ref was not marked read-only")
	}
	if got := store.DefaultManifestVersion(); got != "v1" {
		t.Fatalf("DefaultManifestVersion() = %q, want v1", got)
	}
	if got := store.Snapshot().DefaultManifestVersion; got != "v1" {
		t.Fatalf("Snapshot().DefaultManifestVersion = %q, want v1", got)
	}
}

func TestOpenLayeredRejectsRefConflict(t *testing.T) {
	defaultDir := t.TempDir()
	userDir := t.TempDir()
	pub, priv, err := ed25519.GenerateKey(nil)
	if err != nil {
		t.Fatal(err)
	}
	env := Envelope{APIVersion: "sysarmor.content/v1", Kind: "contextset", Metadata: Metadata{ID: "ctx:conflict", Version: "v1"}, Spec: json.RawMessage(`{"value_type":"string","values":["value"]}`)}
	writeDefaultContent(t, defaultDir, priv, "context.json", env)
	if err := os.WriteFile(filepath.Join(userDir, "context.json"), []byte(signedContent(t, priv, env)), 0o644); err != nil {
		t.Fatal(err)
	}

	_, err = OpenLayered(Options{DefaultDir: defaultDir, Dir: userDir, TrustedKeys: map[string]ed25519.PublicKey{"test": pub}})
	if err == nil {
		t.Fatal("OpenLayered() conflict error = nil")
	}
}

func TestLayeredStoreRejectsDefaultRefUpdate(t *testing.T) {
	defaultDir := t.TempDir()
	pub, priv, err := ed25519.GenerateKey(nil)
	if err != nil {
		t.Fatal(err)
	}
	env := Envelope{APIVersion: "sysarmor.content/v1", Kind: "contextset", Metadata: Metadata{ID: "ctx:readonly", Version: "v1"}, Spec: json.RawMessage(`{"value_type":"string","values":["value"]}`)}
	writeDefaultContent(t, defaultDir, priv, "context.json", env)
	store, err := OpenLayered(Options{DefaultDir: defaultDir, Dir: t.TempDir(), TrustedKeys: map[string]ed25519.PublicKey{"test": pub}})
	if err != nil {
		t.Fatal(err)
	}
	env.Metadata.Version = "v2"
	_, _, err = store.Prepare(signedContent(t, priv, env), false)
	if err == nil {
		t.Fatal("Prepare() default ref update error = nil")
	}
}

func TestOpenLayeredRejectsUnlistedDefaultJSON(t *testing.T) {
	defaultDir := t.TempDir()
	pub, priv, err := ed25519.GenerateKey(nil)
	if err != nil {
		t.Fatal(err)
	}
	env := Envelope{APIVersion: "sysarmor.content/v1", Kind: "contextset", Metadata: Metadata{ID: "ctx:listed", Version: "v1"}, Spec: json.RawMessage(`{"value_type":"string","values":["value"]}`)}
	writeDefaultContent(t, defaultDir, priv, "listed.json", env)
	if err := os.WriteFile(filepath.Join(defaultDir, "stale.json"), []byte(signedContent(t, priv, env)), 0o644); err != nil {
		t.Fatal(err)
	}

	_, err = OpenLayered(Options{DefaultDir: defaultDir, Dir: t.TempDir(), TrustedKeys: map[string]ed25519.PublicKey{"test": pub}})
	if err == nil {
		t.Fatal("OpenLayered() unlisted JSON error = nil")
	}
}

func writeDefaultContent(t *testing.T, dir string, privateKey ed25519.PrivateKey, name string, env Envelope) {
	t.Helper()
	raw := signedContent(t, privateKey, env)
	if err := os.WriteFile(filepath.Join(dir, name), []byte(raw), 0o644); err != nil {
		t.Fatal(err)
	}
	manifest := Manifest{
		Version: "v1",
		Entries: []ManifestEntry{{
			Ref: env.Metadata.ID, Kind: env.Kind, Version: env.Metadata.Version,
			Digest: signedDigest(env), File: name,
		}},
	}
	data, err := json.Marshal(manifest)
	if err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(dir, "content-manifest.json"), data, 0o644); err != nil {
		t.Fatal(err)
	}
}
