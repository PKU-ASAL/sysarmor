package sqlite

import (
	"bytes"
	"crypto/sha256"
	"database/sql"
	"encoding/hex"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func policyRecord(kind string, version uint64, document string) PolicyRecord {
	digest := sha256.Sum256([]byte(document))
	return PolicyRecord{Kind: kind, Version: version, Document: []byte(document), Digest: hex.EncodeToString(digest[:])}
}

func activateManagedPolicyForTest(t *testing.T, store *Store, policy PolicyRecord) {
	t.Helper()
	enrollment, err := store.Enrollment(t.Context())
	if err != nil {
		t.Fatal(err)
	}
	if enrollment.State == StateStandalone {
		enrollment = testManagedEnrollment()
		if err := store.SetEnrolling(t.Context(), enrollment); err != nil {
			t.Fatal(err)
		}
	}
	if err := store.ActivateManagedPolicy(t.Context(), policy); err != nil {
		t.Fatal(err)
	}
}

func TestPolicyReplaceSurvivesReopen(t *testing.T) {
	root := filepath.Join(t.TempDir(), "agent")
	store := openStore(t, root)
	want := policyRecord("detection", 7, `{"policy_id":"p1"}`)
	if err := store.PutPolicy(t.Context(), want); err != nil {
		t.Fatal(err)
	}
	want.Version = 8
	want = policyRecord("detection", 8, `{"policy_id":"p2"}`)
	if err := store.PutPolicy(t.Context(), want); err != nil {
		t.Fatal(err)
	}
	if err := store.Close(); err != nil {
		t.Fatal(err)
	}

	store = openStore(t, root)
	defer store.Close()
	got, ok, err := store.Policy(t.Context(), "detection")
	if err != nil || !ok {
		t.Fatalf("policy ok=%t err=%v", ok, err)
	}
	if got.Version != want.Version || got.Digest != want.Digest || !bytes.Equal(got.Document, want.Document) {
		t.Fatalf("policy=%+v want=%+v", got, want)
	}
}

func TestPutPolicyRejectsVersionRollback(t *testing.T) {
	store := openStore(t, t.TempDir())
	defer store.Close()

	if err := store.PutPolicy(t.Context(), policyRecord("endpoint", 2, `{"policy_id":"v2"}`)); err != nil {
		t.Fatal(err)
	}
	err := store.PutPolicy(t.Context(), policyRecord("endpoint", 1, `{"policy_id":"v1"}`))
	if err == nil || !strings.Contains(err.Error(), "version rollback") {
		t.Fatalf("rollback error = %v", err)
	}
}

func TestPutPolicyRejectsSameVersionDifferentDigest(t *testing.T) {
	store := openStore(t, t.TempDir())
	defer store.Close()

	if err := store.PutPolicy(t.Context(), policyRecord("endpoint", 2, `{"policy_id":"v2"}`)); err != nil {
		t.Fatal(err)
	}
	err := store.PutPolicy(t.Context(), policyRecord("endpoint", 2, `{"policy_id":"other"}`))
	if err == nil || !strings.Contains(err.Error(), "digest conflict") {
		t.Fatalf("digest conflict error = %v", err)
	}
}

func TestPutPolicyRejectsSameVersionTamperedDocument(t *testing.T) {
	store := openStore(t, t.TempDir())
	defer store.Close()

	want := policyRecord("endpoint", 2, `{"policy_id":"v2"}`)
	if err := store.PutPolicy(t.Context(), want); err != nil {
		t.Fatal(err)
	}
	err := store.PutPolicy(t.Context(), PolicyRecord{Kind: want.Kind, Version: want.Version, Document: []byte(`{"policy_id":"tampered"}`), Digest: want.Digest})
	if err == nil || !strings.Contains(err.Error(), "digest mismatch") {
		t.Fatalf("tampered document error = %v", err)
	}
}

func TestPutPolicyRejectsDigestMismatch(t *testing.T) {
	store := openStore(t, t.TempDir())
	defer store.Close()
	err := store.PutPolicy(t.Context(), PolicyRecord{Kind: "endpoint", Version: 1, Document: []byte(`{"policy_id":"v1"}`), Digest: "wrong"})
	if err == nil || !strings.Contains(err.Error(), "digest mismatch") {
		t.Fatalf("digest mismatch error = %v", err)
	}
}

func TestPolicySlotsPreserveSourcesAndActivation(t *testing.T) {
	store := openStore(t, t.TempDir())
	defer store.Close()
	standalone := policyRecord("endpoint", 1, `{"policy_id":"standalone"}`)
	managed := policyRecord("endpoint", 5, `{"policy_id":"managed"}`)
	if err := store.PutAndActivateStandalonePolicy(t.Context(), standalone); err != nil {
		t.Fatal(err)
	}
	activateManagedPolicyForTest(t, store, managed)
	active, source, ok, err := store.ActivePolicy(t.Context(), "endpoint")
	if err != nil || !ok || source != PolicySourceManaged || active.Version != managed.Version {
		t.Fatalf("active=%+v source=%q ok=%t err=%v", active, source, ok, err)
	}
	preserved, ok, err := store.PolicySlot(t.Context(), "endpoint", PolicySourceStandalone)
	if err != nil || !ok || preserved.Version != standalone.Version {
		t.Fatalf("standalone=%+v ok=%t err=%v", preserved, ok, err)
	}
}

func TestOpenMigratesLegacyPolicyToStandaloneSlot(t *testing.T) {
	root := filepath.Join(t.TempDir(), "agent")
	if err := os.MkdirAll(root, 0o700); err != nil {
		t.Fatal(err)
	}
	db, err := sql.Open("sqlite", filepath.Join(root, "agent.db"))
	if err != nil {
		t.Fatal(err)
	}
	legacy := policyRecord("endpoint", 7, `{"policy_id":"legacy"}`)
	if _, err := db.Exec(`CREATE TABLE schema_meta(version INTEGER PRIMARY KEY); INSERT INTO schema_meta(version) VALUES (1);
CREATE TABLE policy(kind TEXT PRIMARY KEY, version INTEGER NOT NULL, document_json BLOB NOT NULL, digest TEXT NOT NULL, updated_at_ns INTEGER NOT NULL);`); err != nil {
		t.Fatal(err)
	}
	if _, err := db.Exec(`INSERT INTO policy(kind, version, document_json, digest, updated_at_ns) VALUES (?, ?, ?, ?, 1)`, legacy.Kind, legacy.Version, legacy.Document, legacy.Digest); err != nil {
		t.Fatal(err)
	}
	if err := db.Close(); err != nil {
		t.Fatal(err)
	}

	store := openStore(t, root)
	defer store.Close()
	active, source, ok, err := store.ActivePolicy(t.Context(), "endpoint")
	if err != nil || !ok || source != PolicySourceStandalone || active.Version != legacy.Version || !bytes.Equal(active.Document, legacy.Document) {
		t.Fatalf("active=%+v source=%q ok=%t err=%v", active, source, ok, err)
	}
	if got := schemaVersion(t, store); got != currentSchemaVersion {
		t.Fatalf("schema version=%d", got)
	}
}

func TestOpenMigratesManagedLegacyPolicyWithoutFabricatingStandalone(t *testing.T) {
	root := filepath.Join(t.TempDir(), "agent")
	if err := os.MkdirAll(root, 0o700); err != nil {
		t.Fatal(err)
	}
	db, err := sql.Open("sqlite", filepath.Join(root, "agent.db"))
	if err != nil {
		t.Fatal(err)
	}
	legacy := policyRecord("endpoint", 7, `{"policy_id":"managed-legacy"}`)
	if _, err := db.Exec(`CREATE TABLE schema_meta(version INTEGER PRIMARY KEY); INSERT INTO schema_meta(version) VALUES (1);
CREATE TABLE enrollment(singleton INTEGER PRIMARY KEY, state TEXT NOT NULL, tenant_id TEXT, agent_id TEXT, gateway_address TEXT, tls_ca_path TEXT, tls_cert_path TEXT, tls_key_path TEXT, tls_server_name TEXT, upload_history INTEGER NOT NULL, managed_from_seq INTEGER, updated_at_ns INTEGER NOT NULL);
INSERT INTO enrollment VALUES (1,'managed','tenant-a','agent-a','gateway','/ca','/cert','/key','',0,1,1);
CREATE TABLE policy(kind TEXT PRIMARY KEY, version INTEGER NOT NULL, document_json BLOB NOT NULL, digest TEXT NOT NULL, updated_at_ns INTEGER NOT NULL);`); err != nil {
		t.Fatal(err)
	}
	if _, err := db.Exec(`INSERT INTO policy VALUES (?, ?, ?, ?, 1)`, legacy.Kind, legacy.Version, legacy.Document, legacy.Digest); err != nil {
		t.Fatal(err)
	}
	if err := db.Close(); err != nil {
		t.Fatal(err)
	}
	store := openStore(t, root)
	defer store.Close()
	active, source, ok, err := store.ActivePolicy(t.Context(), "endpoint")
	if err != nil || !ok || source != PolicySourceManaged || active.Version != legacy.Version {
		t.Fatalf("active=%+v source=%q ok=%t err=%v", active, source, ok, err)
	}
	enrollment, err := store.Enrollment(t.Context())
	if err != nil || enrollment.UnenrollmentProtocol != UnenrollmentProtocolLegacyMTLS || enrollment.EnrollmentID != "" || enrollment.CertificateSerial != "" {
		t.Fatalf("migrated enrollment=%+v err=%v", enrollment, err)
	}
	if _, ok, err := store.PolicySlot(t.Context(), "endpoint", PolicySourceStandalone); err != nil || ok {
		t.Fatalf("fabricated standalone fallback ok=%t err=%v", ok, err)
	}
}

func TestOpenPreservesLegacyEndpointPolicyWithoutInference(t *testing.T) {
	root := filepath.Join(t.TempDir(), "agent")
	if err := os.MkdirAll(root, 0o700); err != nil {
		t.Fatal(err)
	}
	db, err := sql.Open("sqlite", filepath.Join(root, "agent.db"))
	if err != nil {
		t.Fatal(err)
	}
	legacy := policyRecord("endpoint", 7, `{"policy_id":"managed-legacy","version":7,"collection":{"behaviors":["process.exec"]},"detection":{},"telemetry":{},"response":{}}`)
	if _, err := db.Exec(`CREATE TABLE schema_meta(version INTEGER PRIMARY KEY); INSERT INTO schema_meta(version) VALUES (1);
CREATE TABLE enrollment(singleton INTEGER PRIMARY KEY, state TEXT NOT NULL, tenant_id TEXT, agent_id TEXT, gateway_address TEXT, tls_ca_path TEXT, tls_cert_path TEXT, tls_key_path TEXT, tls_server_name TEXT, upload_history INTEGER NOT NULL, managed_from_seq INTEGER, updated_at_ns INTEGER NOT NULL);
INSERT INTO enrollment VALUES (1,'managed','tenant-a','agent-a','gateway','/ca','/cert','/key','',0,1,1);
CREATE TABLE policy(kind TEXT PRIMARY KEY, version INTEGER NOT NULL, document_json BLOB NOT NULL, digest TEXT NOT NULL, updated_at_ns INTEGER NOT NULL);`); err != nil {
		t.Fatal(err)
	}
	if _, err := db.Exec(`INSERT INTO policy VALUES (?, ?, ?, ?, 1)`, legacy.Kind, legacy.Version, legacy.Document, legacy.Digest); err != nil {
		t.Fatal(err)
	}
	if err := db.Close(); err != nil {
		t.Fatal(err)
	}

	store := openStore(t, root)
	defer store.Close()
	migrated, ok, err := store.PolicySlot(t.Context(), "endpoint", PolicySourceManaged)
	if err != nil || !ok {
		t.Fatalf("managed slot ok=%t err=%v", ok, err)
	}
	if !bytes.Equal(migrated.Document, legacy.Document) || migrated.Digest != legacy.Digest {
		t.Fatalf("legacy endpoint policy was rewritten: got=%+v want=%+v", migrated, legacy)
	}
	var legacyDocument []byte
	var legacyDigest string
	if err := store.db.QueryRow(`SELECT document_json, digest FROM policy WHERE kind='endpoint'`).Scan(&legacyDocument, &legacyDigest); err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(legacyDocument, legacy.Document) || legacyDigest != legacy.Digest {
		t.Fatalf("legacy policy and managed slot diverged")
	}
}

func TestPutAndActivateStandalonePolicyIsAtomic(t *testing.T) {
	store := openStore(t, t.TempDir())
	defer store.Close()
	standalone := policyRecord("endpoint", 2, `{"policy_id":"standalone"}`)
	if err := store.PutAndActivateStandalonePolicy(t.Context(), standalone); err != nil {
		t.Fatal(err)
	}
	active, source, ok, err := store.ActivePolicy(t.Context(), "endpoint")
	if err != nil || !ok || source != PolicySourceStandalone || active.Digest != standalone.Digest {
		t.Fatalf("active=%+v source=%q ok=%t err=%v", active, source, ok, err)
	}
}

func TestManagedPolicyActivationPromotesEnrollmentAtomically(t *testing.T) {
	store := openStore(t, t.TempDir())
	defer store.Close()
	enrollment := testManagedEnrollment()
	if err := store.SetEnrolling(t.Context(), enrollment); err != nil {
		t.Fatal(err)
	}
	managed := policyRecord("endpoint", 2, `{"policy_id":"managed"}`)
	if err := store.ActivateManagedPolicy(t.Context(), managed); err != nil {
		t.Fatal(err)
	}
	got, err := store.Enrollment(t.Context())
	_, source, ok, activeErr := store.ActivePolicy(t.Context(), "endpoint")
	if err != nil || activeErr != nil || !ok || got.State != StateManaged || source != PolicySourceManaged {
		t.Fatalf("enrollment=%+v source=%q ok=%t err=%v activeErr=%v", got, source, ok, err, activeErr)
	}
}

func TestManagedPolicyActivationRejectsStandaloneEnrollment(t *testing.T) {
	store := openStore(t, t.TempDir())
	defer store.Close()
	err := store.ActivateManagedPolicy(t.Context(), policyRecord("endpoint", 2, `{"policy_id":"managed"}`))
	if err == nil || !strings.Contains(err.Error(), "enrollment") {
		t.Fatalf("activation error = %v", err)
	}
}

func TestStandalonePolicyActivationRejectsManagedEnrollment(t *testing.T) {
	store := openStore(t, t.TempDir())
	defer store.Close()
	standalone := policyRecord("endpoint", 1, `{"policy_id":"standalone"}`)
	managed := policyRecord("endpoint", 2, `{"policy_id":"managed"}`)
	if err := store.PutAndActivateStandalonePolicy(t.Context(), standalone); err != nil {
		t.Fatal(err)
	}
	activateManagedPolicyForTest(t, store, managed)
	activationErr := store.ActivateStandalonePolicy(t.Context(), "endpoint")
	enrollment, err := store.Enrollment(t.Context())
	_, source, ok, activeErr := store.ActivePolicy(t.Context(), "endpoint")
	if activationErr == nil || err != nil || activeErr != nil || !ok || enrollment.State != StateManaged || source != PolicySourceManaged {
		t.Fatalf("activationErr=%v enrollment=%+v source=%q ok=%t err=%v activeErr=%v", activationErr, enrollment, source, ok, err, activeErr)
	}
}

func TestLegacyPolicyQueryReturnsActiveSlot(t *testing.T) {
	store := openStore(t, t.TempDir())
	defer store.Close()
	legacy := policyRecord("endpoint", 1, `{"policy_id":"legacy"}`)
	if err := store.PutPolicy(t.Context(), legacy); err != nil {
		t.Fatal(err)
	}
	managed := policyRecord("endpoint", 5, `{"policy_id":"managed"}`)
	activateManagedPolicyForTest(t, store, managed)
	got, ok, err := store.Policy(t.Context(), "endpoint")
	if err != nil || !ok || got.Version != managed.Version {
		t.Fatalf("policy=%+v ok=%t err=%v", got, ok, err)
	}
}

func TestDesiredPolicyDoesNotReplaceActivePolicy(t *testing.T) {
	store := openStore(t, t.TempDir())
	defer store.Close()
	standalone := policyRecord("endpoint", 1, `{"policy_id":"standalone"}`)
	managed := policyRecord("endpoint", 5, `{"policy_id":"managed"}`)
	if err := store.PutAndActivateStandalonePolicy(t.Context(), standalone); err != nil {
		t.Fatal(err)
	}
	if err := store.PutDesiredManagedPolicy(t.Context(), managed); err != nil {
		t.Fatal(err)
	}
	desired, status, ok, err := store.DesiredPolicy(t.Context(), "endpoint", PolicySourceManaged)
	if err != nil || !ok || status != PolicyStatusPending || desired.Version != managed.Version {
		t.Fatalf("desired=%+v status=%q ok=%t err=%v", desired, status, ok, err)
	}
	active, source, ok, err := store.ActivePolicy(t.Context(), "endpoint")
	if err != nil || !ok || source != PolicySourceStandalone || active.Version != standalone.Version {
		t.Fatalf("active=%+v source=%q ok=%t err=%v", active, source, ok, err)
	}
}

func TestActivatePolicyPromotesDesiredAndClearsPending(t *testing.T) {
	store := openStore(t, t.TempDir())
	defer store.Close()
	applied := policyRecord("endpoint", 5, `{"policy_id":"applied"}`)
	desired := policyRecord("endpoint", 6, `{"policy_id":"desired"}`)
	activateManagedPolicyForTest(t, store, applied)
	if err := store.PutDesiredManagedPolicy(t.Context(), desired); err != nil {
		t.Fatal(err)
	}
	active, source, ok, err := store.ActivePolicy(t.Context(), "endpoint")
	if err != nil || !ok || source != PolicySourceManaged || active.Version != applied.Version {
		t.Fatalf("active=%+v source=%q ok=%t err=%v", active, source, ok, err)
	}
	if err := store.ActivateManagedPolicy(t.Context(), desired); err != nil {
		t.Fatal(err)
	}
	active, source, ok, err = store.ActivePolicy(t.Context(), "endpoint")
	if err != nil || !ok || source != PolicySourceManaged || active.Version != desired.Version {
		t.Fatalf("active=%+v source=%q ok=%t err=%v", active, source, ok, err)
	}
	_, status, ok, err := store.DesiredPolicy(t.Context(), "endpoint", PolicySourceManaged)
	if err != nil || ok || status != "" {
		t.Fatalf("pending status=%q ok=%t err=%v", status, ok, err)
	}
}

func TestManagedPolicyAllowsDifferentIdentityAtSameVersion(t *testing.T) {
	store := openStore(t, t.TempDir())
	defer store.Close()
	balanced := policyRecord("endpoint", 2, `{"policy_id":"balanced"}`)
	deep := policyRecord("endpoint", 2, `{"policy_id":"deep"}`)
	activateManagedPolicyForTest(t, store, balanced)

	if err := store.PutDesiredManagedPolicy(t.Context(), deep); err != nil {
		t.Fatalf("put desired policy: %v", err)
	}
	if err := store.ActivateManagedPolicy(t.Context(), deep); err != nil {
		t.Fatalf("activate policy: %v", err)
	}
	active, source, ok, err := store.ActivePolicy(t.Context(), "endpoint")
	if err != nil || !ok || source != PolicySourceManaged || !bytes.Equal(active.Document, deep.Document) {
		t.Fatalf("active=%+v source=%q ok=%t err=%v", active, source, ok, err)
	}
}

func TestDesiredPolicyRejectsRollbackFromAppliedSlot(t *testing.T) {
	store := openStore(t, t.TempDir())
	defer store.Close()
	applied := policyRecord("endpoint", 5, `{"policy_id":"managed"}`)
	rollback := policyRecord("endpoint", 4, `{"policy_id":"managed"}`)
	activateManagedPolicyForTest(t, store, applied)
	if err := store.PutDesiredManagedPolicy(t.Context(), rollback); err == nil {
		t.Fatal("expected desired policy rollback rejection")
	}
}

func TestPendingManagedPolicyDoesNotReplaceAppliedPolicyAfterRestart(t *testing.T) {
	root := t.TempDir()
	store := openStore(t, root)
	applied := policyRecord("endpoint", 5, `{"policy_id":"applied"}`)
	desired := policyRecord("endpoint", 6, `{"policy_id":"desired"}`)
	activateManagedPolicyForTest(t, store, applied)
	if err := store.PutDesiredManagedPolicy(t.Context(), desired); err != nil {
		t.Fatal(err)
	}
	if err := store.Close(); err != nil {
		t.Fatal(err)
	}

	store = openStore(t, root)
	defer store.Close()
	active, source, ok, err := store.ActivePolicy(t.Context(), "endpoint")
	if err != nil || !ok || source != PolicySourceManaged || active.Version != applied.Version {
		t.Fatalf("active=%+v source=%q ok=%t err=%v", active, source, ok, err)
	}
	pending, status, ok, err := store.DesiredPolicy(t.Context(), "endpoint", PolicySourceManaged)
	if err != nil || !ok || status != PolicyStatusPending || pending.Version != desired.Version {
		t.Fatalf("pending=%+v status=%q ok=%t err=%v", pending, status, ok, err)
	}
}

func TestStandaloneActivationClearsManagedDesiredPolicy(t *testing.T) {
	store := openStore(t, t.TempDir())
	defer store.Close()
	standalone := policyRecord("endpoint", 1, `{"policy_id":"standalone"}`)
	managed := policyRecord("endpoint", 5, `{"policy_id":"managed"}`)
	if err := store.PutAndActivateStandalonePolicy(t.Context(), standalone); err != nil {
		t.Fatal(err)
	}
	if err := store.PutDesiredManagedPolicy(t.Context(), managed); err != nil {
		t.Fatal(err)
	}
	if err := store.ActivateStandalonePolicy(t.Context(), "endpoint"); err != nil {
		t.Fatal(err)
	}
	_, _, ok, err := store.DesiredPolicy(t.Context(), "endpoint", PolicySourceManaged)
	if err != nil || ok {
		t.Fatalf("managed desired remains after standalone activation: ok=%t err=%v", ok, err)
	}
}
