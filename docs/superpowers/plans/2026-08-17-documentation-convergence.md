# Documentation and Security Vocabulary Convergence Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Establish one canonical security vocabulary and a task-oriented public documentation tree, then remove historical process, commercial, scratchpad, and legacy Detection terminology from the maintained project.

**Architecture:** `docs/concepts/security-data-model.md` becomes the only definition of Event, Signal, Stage, DetectorKind, Where, Evidence, and Incident. Public documents reference that model according to their tutorial, explanation, guide, reference, operations, or development role; architecture contracts enforce the tree and vocabulary. Historical specs/plans and commercial artifacts leave the worktree after durable decisions are moved into public docs.

**Tech Stack:** Markdown, Python `unittest`, Go 1.26, Protobuf, GNU Make, Bash, Git.

## Global Constraints

- Production contracts, production code, formal docs, formal tests, and reports use the canonical vocabulary with no alias, redirect page, dual read, or fallback.
- Detection `Terminal` is allowed only in Protobuf reserved declarations, the minimal OpenSearch v1 migration fixture, ordinary non-Detection lifecycle terminology, and a future internal `SteinerTerminal`.
- `Graph Conclusion` is a target capability until a real production generator exists.
- Completed `docs/superpowers/` and `docs/business/` content is archived only in Git history.
- Formal build, test, and documentation paths do not depend on `.scratchpad/`.
- Do not delete ignored local `.scratchpad` data.
- Keep production functions below 50 lines and production files below 500 lines.
- Use TDD and keep every commit focused and buildable.

---

### Task 1: Lock the Public Documentation Contract

**Files:**
- Create: `test/contracts/test_documentation.py`
- Modify: `test/Makefile`
- Modify: `.github/workflows/architecture.yml`

**Interfaces:**
- Produces: `DocumentationContractTest`, the repository gate for canonical paths, links, vocabulary, and scratchpad independence.
- Consumes: the target tree and exceptions defined in the approved design spec.

- [ ] **Step 1: Add the failing documentation contract**

Create `test/contracts/test_documentation.py` with checks for:

```python
REQUIRED = (
    "CONTRIBUTING.md",
    "docs/README.md",
    "docs/quickstart.md",
    "docs/design-principles.md",
    "docs/architecture.md",
    "docs/roadmap.md",
    "docs/concepts/security-data-model.md",
    "docs/guides/agent-management.md",
    "docs/guides/policy.md",
    "docs/guides/investigation.md",
    "docs/operations/deployment.md",
    "docs/operations/maintenance.md",
    "docs/reference/configuration.md",
    "docs/reference/api.md",
    "docs/reference/cli.md",
    "docs/development/testing.md",
)
RETIRED = (
    "CATALOG.md",
    "docs/index.md",
    "docs/design-principles.zh-CN.md",
    "docs/development/development.md",
    "docs/development/debug.md",
    "docs/business",
    "docs/superpowers",
)
CANONICAL_PHRASES = (
    "Event 是事实",
    "Signal 是发现",
    "Evidence 是依据",
    "Incident 是安全分析报告",
    "Rule Candidate",
    "Rule Conclusion",
    "Model Candidate",
    "Graph Conclusion",
    "System Conclusion",
)
RETIRED_DETECTION_LANGUAGE = re.compile(
    r"terminal signal|terminal state|Learning Signal|Model Signal", re.I
)
```

Implement five tests:

1. Required files exist and retired paths do not.
2. `docs/concepts/security-data-model.md` contains every canonical phrase and says Graph has no production generator.
3. Formal docs, `test/contracts`, Learning report sources, and the attacker helper contain no retired Detection language.
4. Root/test Makefiles, release builder, endpoint/topology archive resolvers, Deployment, and Testing contain no `.scratchpad/.cache`.
5. Relative Markdown links resolve for root READMEs, CONTRIBUTING, maintained `docs/**/*.md`, and layer READMEs; exclude the pending-retirement `docs/superpowers/` and `docs/business/` trees, and skip empty fragments, `mailto:`, and external URLs.

- [ ] **Step 2: Wire the contract into local and CI gates**

Add:

```make
.PHONY: test-unit test-layered-architecture test-documentation-contract

test-unit: test-layered-architecture test-documentation-contract

test-documentation-contract:
	cd .. && python3 -m unittest test.contracts.test_documentation -v
```

Add to `.github/workflows/architecture.yml`:

```yaml
      - name: Verify documentation contract
        run: python3 -m unittest test.contracts.test_documentation -v
```

- [ ] **Step 3: Verify RED**

Run:

```bash
python3 -m unittest test.contracts.test_documentation -v
```

Expected: failures identify missing canonical files, retired paths, stale terminology, scratchpad fallbacks, and future links.

- [ ] **Step 4: Commit**

```bash
git add test/contracts/test_documentation.py test/Makefile .github/workflows/architecture.yml
git commit -m "test(docs): lock canonical documentation contracts"
```

### Task 2: Establish the Canonical Security Data Model

**Files:**
- Create: `docs/concepts/security-data-model.md`
- Modify: `packages/contracts/proto/signal/v1/signal.proto`
- Generate: `packages/contracts/proto/signal/v1/signal.pb.go`
- Modify: `apps/manager/internal/adapters/contracts/signal_mapper.go`
- Modify: `apps/manager/internal/adapters/contracts/telemetry_mapper_test.go`

**Interfaces:**
- Produces: the unique prose definition and documented wire dimensions `SignalStage`, `DetectorKind`, and `SignalWhere`.
- Produces: `validateModelCandidate(*signalv1.Signal) error` with unchanged fail-closed behavior.

- [ ] **Step 1: Write the canonical Concepts document**

Use these exact top-level sections:

```markdown
# 安全数据模型

Event 是事实，Signal 是发现，Evidence 是依据，Incident 是安全分析报告。

## Event：事实
## Signal：发现
## Stage：发现成熟度
## DetectorKind：检测方法
## Where：产生位置
## Evidence：可复核依据
## Incident：安全分析报告
## 数据流与引用
## 当前能力与目标能力
## 不变量
```

The Stage section states Candidate cannot independently converge an Incident, Conclusion can, and promotion creates a new Signal with `signal_refs`. Include Rule Candidate, Rule Conclusion, Model Candidate, Graph Conclusion, and System Conclusion. State that Graph has a contract but no production generator. Restrict Terminal to reserved/migration/lifecycle/internal-algorithm uses.

- [ ] **Step 2: Document and tighten wire terminology**

Add comments above `SignalWhere`, `SignalStage`, `DetectorKind`, and fields 3, 25, 26. Rename only the private validator:

```go
if value.GetDetectorKind() == signalv1.DetectorKind_DETECTOR_KIND_MODEL {
	return validateModelCandidate(value)
}

func validateModelCandidate(value *signalv1.Signal) error {
```

Replace the old error with `model detector output must be a candidate`; add a mapper test proving Model Conclusion is rejected with that exact message. This is a direct terminology migration, not an error-text compatibility path.

- [ ] **Step 3: Regenerate and verify GREEN**

```bash
make api
go test ./apps/manager/internal/adapters/contracts -count=1
python3 -m unittest test.contracts.test_layered_architecture -v
```

Expected: all pass.

- [ ] **Step 4: Commit**

```bash
git add docs/concepts/security-data-model.md packages/contracts/proto/signal/v1/signal.proto packages/contracts/proto/signal/v1/signal.pb.go apps/manager/internal/adapters/contracts/signal_mapper.go apps/manager/internal/adapters/contracts/telemetry_mapper_test.go
git commit -m "docs: establish canonical security data model"
```

### Task 3: Reorganize the Public Documentation

**Files:**
- Rename: `docs/index.md` to `docs/README.md`
- Rename: `docs/design-principles.zh-CN.md` to `docs/design-principles.md`
- Modify: `README.md`, `README.zh-CN.md`, `CONTRIBUTING.md`
- Modify: `docs/{README,design-principles,architecture,roadmap}.md`
- Modify: `docs/guides/{policy,investigation}.md`
- Modify: `docs/reference/api.md`
- Modify: `docs/development/testing.md`
- Delete: `docs/development/{development,debug}.md`
- Modify: `apps/{agent,manager}/internal/{domain,application,ports,adapters,bootstrap}/README.md`
- Delete: `CATALOG.md`

**Interfaces:**
- Consumes: Concepts as the only vocabulary definition.
- Produces: the three valid reading paths and governance at `docs/README.md`.

- [ ] **Step 1: Move paths without compatibility copies**

```bash
git mv docs/index.md docs/README.md
git mv docs/design-principles.zh-CN.md docs/design-principles.md
```

- [ ] **Step 2: Merge navigation and governance**

Keep the task table, add Concepts after Quickstart, and merge from CATALOG: one source per topic, current/target/research separation, Proto/CLI/Makefile facts, no process output in public docs, results under `.results/`, and explicit page responsibility.

- [ ] **Step 3: Remove duplicate concept definitions**

Design Principles and Architecture link to Concepts instead of redefining the four objects. Preserve production flows, safety invariants, and failure boundaries. Policy, Investigation, API, and Roadmap use Stage/DetectorKind/Where and label Graph Conclusion as target.

- [ ] **Step 4: Consolidate contributor documentation**

Move repository ownership, dependency rules, build commands, Proto/config procedures, release/UI workflows, deployment ownership, and pre-commit checks into `CONTRIBUTING.md`. Move the active Tetragon identity limitation from `debug.md` to Testing troubleshooting. Delete both source files.

- [ ] **Step 5: Replace historical links in layer READMEs**

Use exactly:

```markdown
维护规则见仓库根目录的 [CONTRIBUTING](../../../../CONTRIBUTING.md)。
```

- [ ] **Step 6: Update links and delete CATALOG**

Update all links to `docs/README.md`, `design-principles.md`, `CONTRIBUTING.md`, and Concepts. Delete CATALOG after its rules are present in docs README.

- [ ] **Step 7: Verify focused links GREEN**

```bash
python3 -m unittest test.contracts.test_layered_architecture.LayeredArchitectureContractTest.test_layer_governance_links_resolve -v
python3 -m unittest test.contracts.test_documentation.DocumentationContractTest.test_public_markdown_links_resolve -v
```

Expected: both pass; full docs contract remains RED only for later tasks.

- [ ] **Step 8: Commit**

```bash
git add -A README.md README.zh-CN.md CONTRIBUTING.md CATALOG.md docs apps/agent/internal apps/manager/internal
git commit -m "docs: reorganize public documentation"
```

### Task 4: Remove Scratchpad Build and Test Dependencies

**Files:**
- Modify: `Makefile`, `test/Makefile`
- Modify: `deployments/packages/build-release.sh`
- Modify: `test/suites/functional/topology/scenario-container.sh`
- Modify: `test/suites/functional/endpoint/e2e-namespace-self-container.sh`
- Modify: `packages/contracts/schema/agent_test_assets_test.go`
- Modify: `docs/operations/deployment.md`, `docs/development/testing.md`

**Interfaces:**
- Produces: archive resolution from `SYSARMOR_TETRAGON_ARCHIVE` or repository `.cache/` only.
- Preserves: local scratchpad data and VM archive exclusion.

- [ ] **Step 1: Change test expectations**

Remove the scratchpad archive from accepted asset strings and assert the release builder does not contain `.scratchpad/.cache`.

- [ ] **Step 2: Verify RED**

```bash
go test ./packages/contracts/schema -count=1
python3 -m unittest test.contracts.test_documentation.DocumentationContractTest.test_formal_build_paths_do_not_depend_on_scratchpad_cache -v
```

Expected: failures identify current fallback paths.

- [ ] **Step 3: Remove all fallbacks**

Use only `.cache/tetragon-v1.7.0-amd64.tar.gz` as the implicit candidate. Doctor text supports an explicit environment path or `.cache/`. Keep scratchpad in VM exclusion lists because exclusion is not a dependency.

- [ ] **Step 4: Verify GREEN and commit**

```bash
go test ./packages/contracts/schema -count=1
python3 -m unittest test.contracts.test_documentation.DocumentationContractTest.test_formal_build_paths_do_not_depend_on_scratchpad_cache -v
git add Makefile test/Makefile deployments/packages/build-release.sh test/suites/functional/topology/scenario-container.sh test/suites/functional/endpoint/e2e-namespace-self-container.sh packages/contracts/schema/agent_test_assets_test.go docs/operations/deployment.md docs/development/testing.md
git commit -m "refactor: remove scratchpad runtime dependencies"
```

### Task 5: Align Detection Tests and Learning Reports

**Files:**
- Modify: `test/contracts/agent-test-coverage.tsv`
- Modify: `test/environments/container/images/attacker/payloads/helper`
- Modify: `test/suites/performance/learning/{report,test_report,learning_report_renderer}.py`

**Interfaces:**
- Produces: report key `model_candidates`; samples retain `stage`, `detectorKind`, and `where`.
- Preserves: report verdicts, score math, truth evaluation, and Rule behavior.

- [ ] **Step 1: Convert tests to the desired contract**

Replace fixture key `model_signals` with `model_candidates`. Assert Model Candidates heading and candidate tuple:

```python
{
    "stage": "SIGNAL_STAGE_CANDIDATE",
    "detectorKind": "DETECTOR_KIND_MODEL",
    "where": "SIGNAL_WHERE_ENDPOINT",
}
```

- [ ] **Step 2: Verify RED**

```bash
python3 -m unittest test.suites.performance.learning.test_report -v
```

Expected: failures because production report code still consumes `model_signals`.

- [ ] **Step 3: Rename report internals**

Rename dictionary keys, variables, helper parameters, and lookups to `model_candidates`. Keep generic `signals` for wire input and `rule_signals` because Rule results can have both stages. Ensure samples include all three dimensions.

- [ ] **Step 4: Remove stale Terminal prose**

Use System Conclusion, expected Conclusion, no Conclusion, and endpoint reverse-shell Conclusion in the coverage rows and helper comment. Do not alter ordinary transport/control terminal terminology.

- [ ] **Step 5: Verify GREEN and commit**

```bash
python3 -m unittest test.suites.performance.learning.test_report -v
python3 -m unittest test.contracts.test_documentation.DocumentationContractTest.test_formal_sources_do_not_use_retired_detection_language -v
git add test/contracts/agent-test-coverage.tsv test/environments/container/images/attacker/payloads/helper test/suites/performance/learning
git commit -m "test: align learning and detection terminology"
```

### Task 6: Retire Commercial and Historical Documentation

**Files:**
- Modify: `Makefile`, `.gitignore`, `test/contracts/test_documentation.py`
- Delete: `docs/business/`, `tools/docs/`, `test/suites/docs/`, `docs/superpowers/`

**Interfaces:**
- Consumes: durable decisions already moved to public docs.
- Produces: no maintained commercial generator or historical process tree; Git history is the archive.

- [ ] **Step 1: Extend retirement tests**

Add `tools/docs` and `test/suites/docs` to retired paths and:

```python
def test_commercial_document_tooling_is_retired(self):
    makefile = (self.repo / "Makefile").read_text()
    for token in ("business-docx", "BUSINESS_DOCX_SOURCE", "BUSINESS_DOCX_OUTPUT"):
        self.assertNotIn(token, makefile)
```

- [ ] **Step 2: Verify RED**

```bash
python3 -m unittest test.contracts.test_documentation.DocumentationContractTest.test_public_document_tree_is_canonical test.contracts.test_documentation.DocumentationContractTest.test_commercial_document_tooling_is_retired -v
```

Expected: failures list commercial tooling and process docs.

- [ ] **Step 3: Remove commercial tooling**

Remove business targets, variables, PHONY names, and help lines from Makefile. Delete `docs/business/`, `tools/docs/`, and `test/suites/docs/`. Remove the `docs/business/` ignore entry.

- [ ] **Step 4: Verify no maintained historical links**

```bash
rg -n "docs/superpowers|superpowers/specs|superpowers/plans" README.md README.zh-CN.md CONTRIBUTING.md apps packages docs --glob '!docs/superpowers/**'
```

Expected: no output.

- [ ] **Step 5: Delete all completed process docs**

Delete `docs/superpowers/`, including this spec and plan, and remove its ignore entry. Do not create an archive or redirect.

- [ ] **Step 6: Verify GREEN and commit**

```bash
python3 -m unittest test.contracts.test_documentation -v
git add -A Makefile .gitignore docs tools test
git commit -m "chore: remove historical process documentation"
```

### Task 7: Run Final Quality Gates

**Files:**
- Modify only files required to fix failures caused by Tasks 1-6.

**Interfaces:**
- Produces: clean worktree and evidence that project behavior is unchanged.

- [ ] **Step 1: Scan structural and vocabulary invariants**

```bash
rg -n "terminal signal|terminal state|Learning Signal|Model Signal" docs test/contracts test/suites/performance/learning test/environments/container/images/attacker/payloads/helper
rg -n "docs/superpowers|docs/business|\.scratchpad/.cache|docs/index.md|design-principles.zh-CN.md|development/development.md" README.md README.zh-CN.md CONTRIBUTING.md Makefile apps packages deployments docs test --glob '!test/.results/**'
```

Expected: no output.

- [ ] **Step 2: Run Python gates**

```bash
python3 -m unittest test.contracts.test_documentation test.contracts.test_layered_architecture test.contracts.test_monorepo_layout -v
python3 -m unittest discover -s test/suites/performance/learning -p 'test_*.py' -v
```

Expected: all pass.

- [ ] **Step 3: Run Go gates**

```bash
go test ./... -count=1
go vet ./...
```

Expected: both pass.

- [ ] **Step 4: Run hygiene gates**

```bash
test -z "$(gofmt -l apps packages)"
git diff --check
git status --short
```

Expected: no formatting output, no diff errors, and no uncommitted files.

- [ ] **Step 5: Manually verify reading paths**

```text
README -> Quickstart -> Concepts
Concepts -> Architecture -> Guide -> Reference
CONTRIBUTING -> Architecture -> Testing
```

Every link resolves and no page redefines the canonical model.

- [ ] **Step 6: Close any gate failure at its owning task**

If a gate fails, return to the task that owns the violated contract, add a focused regression assertion there, make that assertion pass, and amend that task before repeating Steps 1-5. Do not create an empty or mixed-concern final commit.
