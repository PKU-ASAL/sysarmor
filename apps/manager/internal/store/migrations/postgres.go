package migrations

const PostgresVersion = 3

type Migration struct {
	Version int
	Name    string
	SQL     string
}

const AgentUnenrollmentsSchema = `
CREATE TABLE IF NOT EXISTS agent_unenrollments (
  tenant_id TEXT NOT NULL DEFAULT 'default',
  enrollment_id TEXT NOT NULL,
  agent_id TEXT NOT NULL,
  certificate_serial TEXT NOT NULL,
  status TEXT NOT NULL,
  revoked_at TIMESTAMPTZ NOT NULL,
  endpoint_completed_at TIMESTAMPTZ,
  created_at TIMESTAMPTZ NOT NULL DEFAULT now(),
  updated_at TIMESTAMPTZ NOT NULL DEFAULT now(),
  data JSONB NOT NULL,
  PRIMARY KEY (tenant_id, enrollment_id)
);
CREATE INDEX IF NOT EXISTS idx_agent_unenrollments_agent ON agent_unenrollments (tenant_id, agent_id);
CREATE INDEX IF NOT EXISTS idx_agent_unenrollments_status ON agent_unenrollments (tenant_id, status);
`

const TenantTelemetryBatchesSchema = `
CREATE TABLE IF NOT EXISTS telemetry_batches (
  tenant_id TEXT NOT NULL,
  batch_id TEXT NOT NULL,
  status TEXT NOT NULL,
  claim_token TEXT NOT NULL,
  lease_until TIMESTAMPTZ NOT NULL,
  created_at TIMESTAMPTZ NOT NULL DEFAULT now(),
  completed_at TIMESTAMPTZ,
  PRIMARY KEY (tenant_id, batch_id),
  CHECK (status IN ('processing', 'completed'))
);
CREATE INDEX IF NOT EXISTS idx_telemetry_batches_lease
  ON telemetry_batches (status, lease_until);
`

const PostgresSchema = `
CREATE TABLE IF NOT EXISTS schema_migrations (
  version INTEGER PRIMARY KEY,
  applied_at TIMESTAMPTZ NOT NULL DEFAULT now()
);

CREATE TABLE IF NOT EXISTS agents (
  tenant_id TEXT NOT NULL,
  agent_id TEXT NOT NULL,
  host_id TEXT NOT NULL,
  version TEXT NOT NULL DEFAULT '',
  observed_at TIMESTAMPTZ NOT NULL DEFAULT now(),
  data JSONB NOT NULL,
  PRIMARY KEY (tenant_id, agent_id)
);

CREATE TABLE IF NOT EXISTS agent_health (
  tenant_id TEXT NOT NULL,
  agent_id TEXT NOT NULL,
  host_id TEXT NOT NULL DEFAULT '',
  scope_type TEXT NOT NULL DEFAULT '',
  scope_selector TEXT NOT NULL DEFAULT '',
  observed_at TIMESTAMPTZ NOT NULL DEFAULT now(),
  data JSONB NOT NULL,
  PRIMARY KEY (tenant_id, agent_id)
);

CREATE TABLE IF NOT EXISTS rules (
  tenant_id TEXT NOT NULL DEFAULT 'default',
  rule_id TEXT NOT NULL,
  version BIGINT NOT NULL,
  rule_where TEXT NOT NULL,
  enabled BOOLEAN NOT NULL,
  severity INTEGER NOT NULL DEFAULT 0,
  tags TEXT[] NOT NULL DEFAULT '{}',
  mitre TEXT[] NOT NULL DEFAULT '{}',
  data JSONB NOT NULL,
  PRIMARY KEY (tenant_id, rule_id, version)
);

CREATE TABLE IF NOT EXISTS policies (
  tenant_id TEXT NOT NULL,
  policy_id TEXT NOT NULL,
  version BIGINT NOT NULL,
  scope_type TEXT NOT NULL DEFAULT '',
  scope_selector TEXT NOT NULL DEFAULT '',
  mode TEXT NOT NULL DEFAULT 'observe',
  created_at TIMESTAMPTZ NOT NULL DEFAULT now(),
  data JSONB NOT NULL,
  PRIMARY KEY (tenant_id, policy_id, version)
);

CREATE TABLE IF NOT EXISTS policy_assignments (
  tenant_id TEXT NOT NULL,
  assignment_id TEXT NOT NULL,
  agent_id TEXT NOT NULL DEFAULT '',
  scope_type TEXT NOT NULL DEFAULT '',
  scope_selector TEXT NOT NULL DEFAULT '',
  policy_id TEXT NOT NULL,
  policy_version BIGINT NOT NULL,
  created_at TIMESTAMPTZ NOT NULL DEFAULT now(),
  updated_at TIMESTAMPTZ NOT NULL DEFAULT now(),
  data JSONB NOT NULL,
  PRIMARY KEY (tenant_id, assignment_id)
);

CREATE TABLE IF NOT EXISTS policy_audit (
  tenant_id TEXT NOT NULL DEFAULT 'default',
  audit_id TEXT NOT NULL,
  action TEXT NOT NULL DEFAULT '',
  policy_id TEXT NOT NULL DEFAULT '',
  policy_version BIGINT NOT NULL DEFAULT 0,
  assignment_id TEXT NOT NULL DEFAULT '',
  actor TEXT NOT NULL DEFAULT '',
  status TEXT NOT NULL DEFAULT '',
  reason TEXT NOT NULL DEFAULT '',
  created_at TIMESTAMPTZ NOT NULL DEFAULT now(),
  data JSONB NOT NULL,
  PRIMARY KEY (tenant_id, audit_id)
);

CREATE TABLE IF NOT EXISTS enrollments (
  tenant_id TEXT NOT NULL DEFAULT 'default',
  enrollment_id TEXT NOT NULL,
  agent_id TEXT NOT NULL DEFAULT '',
  host_id TEXT NOT NULL DEFAULT '',
  token_hash TEXT NOT NULL DEFAULT '',
  status TEXT NOT NULL DEFAULT 'active',
  created_at TIMESTAMPTZ NOT NULL DEFAULT now(),
  expires_at TIMESTAMPTZ,
  used_at TIMESTAMPTZ,
  data JSONB NOT NULL,
  PRIMARY KEY (tenant_id, enrollment_id)
);

CREATE TABLE IF NOT EXISTS artifacts (
  tenant_id TEXT NOT NULL DEFAULT 'default',
  artifact_id TEXT NOT NULL,
  artifact_name TEXT NOT NULL DEFAULT '',
  artifact_kind TEXT NOT NULL DEFAULT '',
  artifact_version TEXT NOT NULL DEFAULT '',
  artifact_os TEXT NOT NULL DEFAULT '',
  artifact_arch TEXT NOT NULL DEFAULT '',
  sha256 TEXT NOT NULL DEFAULT '',
  size_bytes BIGINT NOT NULL DEFAULT 0,
  status TEXT NOT NULL DEFAULT 'draft',
  storage_path TEXT NOT NULL DEFAULT '',
  created_at TIMESTAMPTZ NOT NULL DEFAULT now(),
  updated_at TIMESTAMPTZ NOT NULL DEFAULT now(),
  data JSONB NOT NULL,
  PRIMARY KEY (tenant_id, artifact_id)
);

CREATE TABLE IF NOT EXISTS artifact_channels (
  tenant_id TEXT NOT NULL DEFAULT 'default',
  channel_name TEXT NOT NULL,
  artifact_id TEXT NOT NULL,
  created_at TIMESTAMPTZ NOT NULL DEFAULT now(),
  updated_at TIMESTAMPTZ NOT NULL DEFAULT now(),
  data JSONB NOT NULL,
  PRIMARY KEY (tenant_id, channel_name)
);

CREATE TABLE IF NOT EXISTS agent_certificates (
  tenant_id TEXT NOT NULL DEFAULT 'default',
  agent_id TEXT NOT NULL DEFAULT '',
  serial_number TEXT NOT NULL,
  enrollment_id TEXT NOT NULL DEFAULT '',
  not_before TIMESTAMPTZ NOT NULL,
  not_after TIMESTAMPTZ NOT NULL,
  created_at TIMESTAMPTZ NOT NULL DEFAULT now(),
  revoked_at TIMESTAMPTZ,
  data JSONB NOT NULL,
  PRIMARY KEY (tenant_id, serial_number)
);

CREATE TABLE IF NOT EXISTS events (
  tenant_id TEXT NOT NULL DEFAULT 'default',
  event_id TEXT NOT NULL,
  event_behavior TEXT NOT NULL DEFAULT '',
  agent_id TEXT NOT NULL DEFAULT '',
  host_id TEXT NOT NULL DEFAULT '',
  observed_at TIMESTAMPTZ NOT NULL DEFAULT now(),
  data JSONB NOT NULL,
  PRIMARY KEY (tenant_id, event_id)
);

CREATE TABLE IF NOT EXISTS signals (
  tenant_id TEXT NOT NULL DEFAULT 'default',
  signal_key TEXT NOT NULL,
  signal_id TEXT NOT NULL DEFAULT '',
  layer TEXT NOT NULL DEFAULT '',
  signal_name TEXT NOT NULL DEFAULT '',
  lineage_id TEXT NOT NULL DEFAULT '',
  terminal BOOLEAN NOT NULL DEFAULT false,
  observed_at TIMESTAMPTZ NOT NULL DEFAULT now(),
  data JSONB NOT NULL,
  PRIMARY KEY (tenant_id, signal_key)
);

CREATE TABLE IF NOT EXISTS response_audit (
  tenant_id TEXT NOT NULL DEFAULT 'default',
  response_id TEXT NOT NULL,
  agent_id TEXT NOT NULL DEFAULT '',
  status TEXT NOT NULL,
  action TEXT NOT NULL DEFAULT '',
  created_at TIMESTAMPTZ NOT NULL DEFAULT now(),
  updated_at TIMESTAMPTZ NOT NULL DEFAULT now(),
  command JSONB NOT NULL,
  ack JSONB,
  PRIMARY KEY (tenant_id, response_id)
);

CREATE TABLE IF NOT EXISTS evidence_pullbacks (
  tenant_id TEXT NOT NULL DEFAULT 'default',
  request_id TEXT NOT NULL,
  agent_id TEXT NOT NULL DEFAULT '',
  incident_id TEXT NOT NULL DEFAULT '',
  status TEXT NOT NULL DEFAULT 'pending',
  created_at TIMESTAMPTZ NOT NULL DEFAULT now(),
  updated_at TIMESTAMPTZ NOT NULL DEFAULT now(),
  data JSONB NOT NULL,
  PRIMARY KEY (tenant_id, request_id)
);

CREATE TABLE IF NOT EXISTS control_commands (
  tenant_id TEXT NOT NULL DEFAULT 'default',
  command_id TEXT NOT NULL,
  agent_id TEXT NOT NULL DEFAULT '',
  command_type TEXT NOT NULL DEFAULT '',
  status TEXT NOT NULL DEFAULT 'pending',
  policy_id TEXT NOT NULL DEFAULT '',
  policy_version BIGINT NOT NULL DEFAULT 0,
  content_ref TEXT NOT NULL DEFAULT '',
  content_kind TEXT NOT NULL DEFAULT '',
  content_version TEXT NOT NULL DEFAULT '',
  actor TEXT NOT NULL DEFAULT '',
  reason TEXT NOT NULL DEFAULT '',
  created_at TIMESTAMPTZ NOT NULL DEFAULT now(),
  updated_at TIMESTAMPTZ NOT NULL DEFAULT now(),
  sent_at TIMESTAMPTZ,
  last_sent_at TIMESTAMPTZ,
  acked_at TIMESTAMPTZ,
  canceled_at TIMESTAMPTZ,
  expired_at TIMESTAMPTZ,
  attempt_count BIGINT NOT NULL DEFAULT 0,
  data JSONB NOT NULL,
  PRIMARY KEY (tenant_id, command_id)
);

CREATE TABLE IF NOT EXISTS agent_sessions (
  tenant_id TEXT NOT NULL DEFAULT 'default',
  session_id TEXT NOT NULL,
  agent_id TEXT NOT NULL DEFAULT '',
  status TEXT NOT NULL DEFAULT '',
  data_transport TEXT NOT NULL DEFAULT '',
  control_transport TEXT NOT NULL DEFAULT '',
  last_ack_cursor TEXT NOT NULL DEFAULT '',
  started_at TIMESTAMPTZ NOT NULL DEFAULT now(),
  last_seen_at TIMESTAMPTZ NOT NULL DEFAULT now(),
  last_data_seen_at TIMESTAMPTZ,
  last_control_seen_at TIMESTAMPTZ,
  closed_at TIMESTAMPTZ,
  data JSONB NOT NULL,
  PRIMARY KEY (tenant_id, session_id)
);

CREATE TABLE IF NOT EXISTS rarity_baseline (
  tenant_id TEXT NOT NULL DEFAULT 'default',
  workload_key TEXT NOT NULL,
  signal_name TEXT NOT NULL,
  signal_count BIGINT NOT NULL DEFAULT 0,
  updated_at TIMESTAMPTZ NOT NULL DEFAULT now(),
  data JSONB NOT NULL,
  PRIMARY KEY (tenant_id, workload_key, signal_name)
);

CREATE TABLE IF NOT EXISTS metrics (
  tenant_id TEXT NOT NULL DEFAULT 'default',
  metric_key TEXT NOT NULL,
  updated_at TIMESTAMPTZ NOT NULL DEFAULT now(),
  data JSONB NOT NULL,
  PRIMARY KEY (tenant_id, metric_key)
);

CREATE INDEX IF NOT EXISTS idx_agents_host_id ON agents (host_id);
CREATE INDEX IF NOT EXISTS idx_agent_health_scope ON agent_health (scope_type, scope_selector);
CREATE INDEX IF NOT EXISTS idx_policy_assignments_agent ON policy_assignments (tenant_id, agent_id);
CREATE INDEX IF NOT EXISTS idx_policy_assignments_scope ON policy_assignments (tenant_id, scope_type, scope_selector);
CREATE INDEX IF NOT EXISTS idx_policy_audit_policy ON policy_audit (tenant_id, policy_id);
CREATE INDEX IF NOT EXISTS idx_policy_audit_actor ON policy_audit (tenant_id, actor);
CREATE INDEX IF NOT EXISTS idx_enrollments_token_hash ON enrollments (token_hash);
CREATE INDEX IF NOT EXISTS idx_enrollments_bootstrap_token_hash ON enrollments ((data->>'bootstrap_token_hash'));
CREATE INDEX IF NOT EXISTS idx_enrollments_status ON enrollments (tenant_id, status);
CREATE INDEX IF NOT EXISTS idx_artifacts_lookup ON artifacts (tenant_id, artifact_kind, status);
CREATE INDEX IF NOT EXISTS idx_artifacts_version ON artifacts (tenant_id, artifact_name, artifact_version);
CREATE INDEX IF NOT EXISTS idx_events_labels ON events USING GIN ((data->'labels'));
CREATE INDEX IF NOT EXISTS idx_events_observed_at ON events (observed_at);
CREATE INDEX IF NOT EXISTS idx_signals_labels_layer ON signals USING GIN ((data->'labels'));
CREATE INDEX IF NOT EXISTS idx_signals_layer ON signals (tenant_id, layer);
CREATE INDEX IF NOT EXISTS idx_signals_lineage ON signals (tenant_id, lineage_id);
CREATE INDEX IF NOT EXISTS idx_response_audit_agent ON response_audit (tenant_id, agent_id);
CREATE INDEX IF NOT EXISTS idx_response_audit_status ON response_audit (tenant_id, status);
CREATE INDEX IF NOT EXISTS idx_evidence_pullbacks_agent ON evidence_pullbacks (tenant_id, agent_id);
CREATE INDEX IF NOT EXISTS idx_evidence_pullbacks_status ON evidence_pullbacks (tenant_id, status);
CREATE INDEX IF NOT EXISTS idx_control_commands_agent ON control_commands (tenant_id, agent_id);
CREATE INDEX IF NOT EXISTS idx_control_commands_status ON control_commands (tenant_id, status);
CREATE INDEX IF NOT EXISTS idx_control_commands_type ON control_commands (tenant_id, command_type);
CREATE INDEX IF NOT EXISTS idx_agent_sessions_agent ON agent_sessions (tenant_id, agent_id);
CREATE INDEX IF NOT EXISTS idx_agent_sessions_status ON agent_sessions (tenant_id, status);
CREATE INDEX IF NOT EXISTS idx_rarity_baseline_workload ON rarity_baseline (tenant_id, workload_key);
CREATE INDEX IF NOT EXISTS idx_rarity_baseline_signal ON rarity_baseline (tenant_id, signal_name);

` + AgentUnenrollmentsSchema

func Ordered() []Migration {
	return []Migration{
		{Version: 1, Name: "current_control_plane_baseline", SQL: PostgresSchema},
		{Version: 2, Name: "agent_unenrollment_lifecycle", SQL: AgentUnenrollmentsSchema},
		{Version: 3, Name: "tenant_telemetry_batches", SQL: TenantTelemetryBatchesSchema},
	}
}
