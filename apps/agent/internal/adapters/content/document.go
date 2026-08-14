package content

import (
	"crypto/ed25519"
	"crypto/sha256"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"sort"
	"strings"
)

func Parse(raw string) (Envelope, error) {
	var env Envelope
	if err := json.Unmarshal([]byte(raw), &env); err != nil {
		return Envelope{}, fmt.Errorf("decode content envelope: %w", err)
	}
	env.Kind = strings.TrimSpace(env.Kind)
	env.Metadata.ID = strings.TrimSpace(env.Metadata.ID)
	env.Metadata.Version = strings.TrimSpace(env.Metadata.Version)
	return env, nil
}

func Validate(env Envelope, raw string, allowUnsigned bool) error {
	return (&Store{}).Validate(env, allowUnsigned)
}

func (s *Store) Validate(env Envelope, allowUnsigned bool) error {
	if env.APIVersion != "sysarmor.content/v1" {
		return fmt.Errorf("unsupported content api_version %q", env.APIVersion)
	}
	switch env.Kind {
	case "rulepack", "contextset", "iocpack", "content-bundle":
	default:
		return fmt.Errorf("unsupported content kind %q", env.Kind)
	}
	if env.Metadata.ID == "" {
		return fmt.Errorf("content metadata.id is required")
	}
	if env.Metadata.Version == "" {
		return fmt.Errorf("content metadata.version is required")
	}
	if len(env.Spec) == 0 || string(env.Spec) == "null" {
		return fmt.Errorf("content spec is required")
	}
	if env.Integrity.Digest != "" {
		if alg := firstNonEmpty(env.Integrity.DigestAlg, "sha256"); alg != "sha256" {
			return fmt.Errorf("unsupported content digest_alg %q", alg)
		}
		if !strings.EqualFold(env.Integrity.Digest, signedDigest(env)) {
			return fmt.Errorf("content digest mismatch")
		}
	}
	if strings.TrimSpace(env.Integrity.Signature) == "" && !allowUnsigned {
		return fmt.Errorf("unsigned content requires allow_unsigned")
	}
	if strings.TrimSpace(env.Integrity.Signature) != "" {
		if err := s.verifySignature(env); err != nil {
			return err
		}
	}
	return nil
}

func (s *Store) verifySignature(env Envelope) error {
	if env.Integrity.SignatureAlg != "ed25519" {
		return fmt.Errorf("unsupported content signature_alg %q", env.Integrity.SignatureAlg)
	}
	keyID := strings.TrimSpace(env.Integrity.KeyID)
	if keyID == "" {
		return fmt.Errorf("content signature key_id is required")
	}
	key := s.trustedKeys[keyID]
	if len(key) != ed25519.PublicKeySize {
		return fmt.Errorf("content signature key %q is not trusted", keyID)
	}
	sig, err := base64.StdEncoding.DecodeString(env.Integrity.Signature)
	if err != nil {
		return fmt.Errorf("decode content signature: %w", err)
	}
	if !ed25519.Verify(key, signedBytes(env), sig) {
		return fmt.Errorf("content signature verification failed")
	}
	return nil
}

func signedDigest(env Envelope) string {
	sum := sha256.Sum256(signedBytes(env))
	return hex.EncodeToString(sum[:])
}

func signedBytes(env Envelope) []byte {
	payload := struct {
		APIVersion string          `json:"api_version"`
		Kind       string          `json:"kind"`
		Metadata   Metadata        `json:"metadata"`
		Spec       json.RawMessage `json:"spec"`
	}{
		APIVersion: env.APIVersion,
		Kind:       env.Kind,
		Metadata:   env.Metadata,
		Spec:       env.Spec,
	}
	data, _ := json.Marshal(payload)
	return data
}

func SignEnvelope(env Envelope, keyID string, privateKey ed25519.PrivateKey) (Envelope, error) {
	keyID = strings.TrimSpace(keyID)
	if keyID == "" {
		return Envelope{}, fmt.Errorf("content signing key_id is required")
	}
	if len(privateKey) != ed25519.PrivateKeySize {
		return Envelope{}, fmt.Errorf("invalid Ed25519 private key")
	}
	env.Integrity = Integrity{}
	env.Integrity = Integrity{
		DigestAlg:    "sha256",
		Digest:       signedDigest(env),
		SignatureAlg: "ed25519",
		KeyID:        keyID,
		Signature:    base64.StdEncoding.EncodeToString(ed25519.Sign(privateKey, signedBytes(env))),
	}
	return env, nil
}

func firstNonEmpty(values ...string) string {
	for _, value := range values {
		if strings.TrimSpace(value) != "" {
			return strings.TrimSpace(value)
		}
	}
	return ""
}

func parseValueSet(record Record) (ValueSet, error) {
	env, err := Parse(record.RawJSON)
	if err != nil {
		return ValueSet{}, err
	}
	var spec struct {
		ValueType string   `json:"value_type"`
		Values    []string `json:"values"`
	}
	if err := json.Unmarshal(env.Spec, &spec); err != nil {
		return ValueSet{}, err
	}
	return ValueSet{
		Ref:       record.Ref,
		Version:   record.Version,
		Digest:    record.Digest,
		ValueType: strings.TrimSpace(spec.ValueType),
		Values:    normalizeValues(spec.Values),
	}, nil
}

func normalizeValues(values []string) []string {
	seen := map[string]bool{}
	var out []string
	for _, value := range values {
		value = strings.TrimSpace(value)
		if value == "" || seen[value] {
			continue
		}
		seen[value] = true
		out = append(out, value)
	}
	sort.Strings(out)
	return out
}

func (s *Store) resolvePatch(env Envelope) (string, Envelope, error) {
	if env.Kind != "contextset" && env.Kind != "iocpack" {
		raw, _ := json.Marshal(env)
		return string(raw), env, nil
	}
	var spec struct {
		BaseVersion   string   `json:"base_version"`
		ValueType     string   `json:"value_type"`
		MergeStrategy string   `json:"merge_strategy"`
		Values        []string `json:"values"`
		Ops           []struct {
			Op    string `json:"op"`
			Value string `json:"value"`
		} `json:"ops"`
	}
	if err := json.Unmarshal(env.Spec, &spec); err != nil {
		return "", Envelope{}, err
	}
	if spec.MergeStrategy != "patch" {
		raw, _ := json.Marshal(env)
		return string(raw), env, nil
	}
	current, ok := s.Get(env.Metadata.ID)
	if !ok {
		return "", Envelope{}, fmt.Errorf("patch base content %s not found", env.Metadata.ID)
	}
	if spec.BaseVersion != "" && current.Version != spec.BaseVersion {
		return "", Envelope{}, fmt.Errorf("patch base_version mismatch: have %s want %s", current.Version, spec.BaseVersion)
	}
	set, err := parseValueSet(current)
	if err != nil {
		return "", Envelope{}, err
	}
	values := map[string]bool{}
	for _, value := range set.Values {
		values[value] = true
	}
	for _, op := range spec.Ops {
		value := strings.TrimSpace(op.Value)
		if value == "" {
			continue
		}
		switch op.Op {
		case "add":
			values[value] = true
		case "remove":
			delete(values, value)
		default:
			return "", Envelope{}, fmt.Errorf("unsupported patch op %q", op.Op)
		}
	}
	var merged []string
	for value := range values {
		merged = append(merged, value)
	}
	sort.Strings(merged)
	resolvedSpec := struct {
		ValueType     string   `json:"value_type,omitempty"`
		MergeStrategy string   `json:"merge_strategy"`
		Values        []string `json:"values"`
	}{
		ValueType:     firstNonEmpty(spec.ValueType, set.ValueType),
		MergeStrategy: "replace",
		Values:        merged,
	}
	specData, err := json.Marshal(resolvedSpec)
	if err != nil {
		return "", Envelope{}, err
	}
	env.Spec = specData
	env.Integrity = Integrity{}
	raw, err := json.Marshal(env)
	if err != nil {
		return "", Envelope{}, err
	}
	return string(raw), env, nil
}

func (s *Store) persistLocked(record Record) error {
	if strings.TrimSpace(s.dir) == "" {
		return nil
	}
	name := safeName(record.Ref) + ".json"
	tmp := filepath.Join(s.dir, name+".tmp")
	dst := filepath.Join(s.dir, name)
	data := []byte(record.RawJSON)
	if !record.Signed {
		wrapped, err := json.Marshal(persistedRecord{
			Admission: &unsignedAdmission{AllowUnsigned: true, Digest: record.Digest},
			Content:   json.RawMessage(record.RawJSON),
		})
		if err != nil {
			return err
		}
		data = wrapped
	}
	if err := os.WriteFile(tmp, data, 0o600); err != nil {
		return err
	}
	return os.Rename(tmp, dst)
}

func decodePersistedContent(data []byte) (string, bool, error) {
	var persisted persistedRecord
	if err := json.Unmarshal(data, &persisted); err != nil {
		return "", false, err
	}
	if persisted.Admission == nil || len(persisted.Content) == 0 {
		return string(data), false, nil
	}
	return string(persisted.Content), persisted.Admission.AllowUnsigned, nil
}

func persistedDigest(data []byte) string {
	var persisted persistedRecord
	if json.Unmarshal(data, &persisted) != nil || persisted.Admission == nil {
		return ""
	}
	return persisted.Admission.Digest
}

func safeName(ref string) string {
	replacer := strings.NewReplacer(":", "_", "/", "_", "\\", "_", " ", "_")
	return replacer.Replace(ref)
}

func parseRulePack(record Record) ([]Rule, error) {
	env, err := Parse(record.RawJSON)
	if err != nil {
		return nil, err
	}
	var spec struct {
		RuleSets []struct {
			ID      string `json:"id"`
			Version string `json:"version"`
			Rules   []struct {
				RuleID   string `json:"rule_id"`
				Version  uint64 `json:"version"`
				Severity string `json:"severity"`
				Runtime  struct {
					Type       string           `json:"type"`
					Entrypoint string           `json:"entrypoint"`
					Expr       RuntimeExpr      `json:"expr"`
					Sequence   RuntimeSequence  `json:"sequence"`
					Correlate  RuntimeCorrelate `json:"correlate"`
				} `json:"runtime"`
				Suppress RuntimeSuppression `json:"suppress"`
				Requires struct {
					Events  []RequiredEvent `json:"events"`
					Context struct {
						Required []string `json:"required"`
						Optional []string `json:"optional"`
					} `json:"context"`
					IOC struct {
						Required []string `json:"required"`
						Optional []string `json:"optional"`
					} `json:"ioc"`
				} `json:"requires"`
				Output struct {
					ResponseIntent ResponseIntent `json:"response_intent"`
					Terminal       *bool          `json:"terminal,omitempty"`
				} `json:"output"`
			} `json:"rules"`
		} `json:"rulesets"`
	}
	if err := json.Unmarshal(env.Spec, &spec); err != nil {
		return nil, err
	}
	var out []Rule
	for _, rs := range spec.RuleSets {
		for _, rule := range rs.Rules {
			out = append(out, Rule{
				RuleID:         rule.RuleID,
				Version:        rule.Version,
				RuleSetRef:     rs.ID,
				Severity:       rule.Severity,
				RuntimeType:    rule.Runtime.Type,
				RuntimeEntry:   rule.Runtime.Entrypoint,
				Expr:           rule.Runtime.Expr,
				Sequence:       rule.Runtime.Sequence,
				Correlate:      rule.Runtime.Correlate,
				Suppression:    rule.Suppress,
				RequiredEvents: rule.Requires.Events,
				ContextRefs:    append(append([]string(nil), rule.Requires.Context.Required...), rule.Requires.Context.Optional...),
				IOCRefs:        append(append([]string(nil), rule.Requires.IOC.Required...), rule.Requires.IOC.Optional...),
				ResponseIntent: rule.Output.ResponseIntent,
				Terminal:       rule.Output.Terminal,
			})
		}
	}
	return out, nil
}
