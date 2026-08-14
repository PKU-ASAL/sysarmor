# Task 11 Shared Business Model Closure Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** 删除无真实跨产品价值的共享业务模型，使 Policy 与 Response 只由 Agent Domain 拥有，同时保持全部生产协议和运行行为不变。

**Architecture:** `apps/agent/internal/domain/policy` 与 `domain/response` 拥有纯业务类型和规则；`apps/agent/internal/adapters` 独占 JSON、Protobuf、Sensor SDK 与配置格式映射。`packages/` 只保留 Agent 与 Manager 共同消费的 `contracts/controlmodel` 和 `contracts/health`，不建立 alias、forwarding package 或双生产路径。

**Tech Stack:** Go 1.x、标准库 `encoding/json`、现有 Protobuf 合同、Python `unittest` 架构合同、项目 Make 验收目标。

## Global Constraints

- 严格执行 RED-GREEN-REFACTOR；每个生产变化前必须观察对应测试因缺失目标行为而失败。
- 不改变默认策略、策略版本、策略作用域、Collection/Detection/Telemetry 与 Response 授权语义。
- JSON、Protobuf、SQLite、Sensor SDK 类型不得进入 Agent Domain。
- 不新增 alias、forwarding package、兼容 facade、legacy exemption 或双生产路径。
- `packages/contracts/controlmodel`、`packages/contracts/health` 与 `legacy_mtls` 跨产品协议保持不变。
- 单个函数不超过 50 行；新建或修改后的非生成文件不超过 500 行。
- Task 11 不修改 PostgreSQL 行为，也不新增 PostgreSQL 双事务并发测试。
- 每个提交只处理一个关注点，并遵循 Conventional Commits。

---

## File Structure

- `apps/agent/internal/domain/policy/endpoint.go`：统一 Policy、Endpoint、Detection、Telemetry 与 Scope 纯业务模型。
- `apps/agent/internal/domain/policy/defaults.go`：默认规则、默认策略和默认 Endpoint 投影。
- `apps/agent/internal/domain/policy/normalize.go`：统一策略与 Detection 的纯归一化规则。
- `apps/agent/internal/domain/policy/*_test.go`：Domain 默认值、归一化和投影行为。
- `apps/agent/internal/adapters/policy/document.go`：统一策略 JSON wire 类型和编解码。
- `apps/agent/internal/adapters/policy/protobuf.go`：Domain Detection 与 Protobuf converge/rarity 显式映射。
- `apps/agent/internal/adapters/contracts/policy.go`：只保留 Domain 到 Sensor SDK 的 Collection 映射；删除 shared-business bridge。
- `apps/agent/internal/adapters/contracts/response.go`：Response JSON wire 与 Domain 显式映射。
- `apps/agent/internal/domain/response/model.go`：Response 纯模型、默认值、归一化与授权入口。
- `apps/agent/internal/domain/response/approval.go`：审批阈值、角色、去重和策略要求。
- `apps/agent/internal/domain/response/*_test.go`：Domain Response 行为测试。
- `test/contracts/test_layered_architecture.py`：Task 11 依赖方向、禁用 import 和无兼容层合同。
- `test/contracts/test_monorepo_layout.py`：共享包白名单与旧业务包不存在合同。
- `packages/README.md`：共享包准入标准及 `controlmodel`、`health` 保留依据。
- 删除 `packages/policy/`、`packages/response/`、`packages/eventmodel/`。

### Task 1: 建立 Task 11 架构合同

**Files:**
- Modify: `test/contracts/test_layered_architecture.py`
- Modify: `test/contracts/test_monorepo_layout.py`

**Interfaces:**
- Consumes: 已批准的 Task 11 设计文档与当前目录结构。
- Produces: 三个旧共享包必须消失、两个跨产品合同必须保留、Agent Domain 禁止外层格式依赖的可执行合同。

- [ ] **Step 1: 写入旧共享包删除合同**

在 `test_monorepo_layout.py` 中将共享目录白名单改为真实跨产品能力，并新增明确的 retired 断言：

```python
def test_shared_capabilities_are_owned_by_packages(self):
    expected = (
        "packages/contracts/proto",
        "packages/contracts/schema",
        "packages/contracts/controlmodel",
        "packages/contracts/health",
        "packages/sensor-sdk/contract",
        "packages/tlsconfig",
    )
    for path in expected:
        with self.subTest(path=path):
            self.assertTrue((self.repo / path).is_dir(), f"missing {path}")

def test_task11_retires_agent_owned_shared_business_models(self):
    for path in ("packages/eventmodel", "packages/policy", "packages/response"):
        with self.subTest(path=path):
            self.assertFalse((self.repo / path).exists(), f"retired package remains: {path}")
```

- [ ] **Step 2: 写入 Domain 与兼容尾巴合同**

在 `test_layered_architecture.py` 增加：

```python
def test_task11_agent_business_models_are_domain_owned(self):
    root = self.repo / "apps/agent/internal"
    for path in ("domain/policy", "domain/response"):
        self.assertTrue((root / path).is_dir(), f"missing Agent domain: {path}")
    forbidden = ("packages/policy", "packages/response", "packages/eventmodel")
    for source in (root / "domain").rglob("*.go"):
        text = source.read_text()
        for imported in forbidden:
            self.assertNotIn(imported, text, f"domain imports retired model: {source}")

def test_task11_has_no_retired_model_imports_or_compatibility_facades(self):
    forbidden = ("packages/policy", "packages/response", "packages/eventmodel")
    for source in self.repo.rglob("*.go"):
        text = source.read_text()
        for imported in forbidden:
            self.assertNotIn(imported, text, f"retired model import remains: {source}")
```

- [ ] **Step 3: 运行合同并确认 RED**

Run:

```bash
python3 -m unittest test.contracts.test_monorepo_layout test.contracts.test_layered_architecture
```

Expected: FAIL，且失败原因明确为 `packages/eventmodel`、`packages/policy`、`packages/response` 仍存在或仍被导入；不得接受语法错误或测试发现错误。

- [ ] **Step 4: 提交 RED 合同**

```bash
git add test/contracts/test_layered_architecture.py test/contracts/test_monorepo_layout.py
git commit -m "test(architecture): define task11 model ownership contracts"
```

### Task 2: 将统一 Policy 迁入 Agent Domain 与 Adapter

**Files:**
- Create: `apps/agent/internal/domain/policy/endpoint.go`
- Create: `apps/agent/internal/domain/policy/defaults.go`
- Create: `apps/agent/internal/domain/policy/normalize.go`
- Create: `apps/agent/internal/domain/policy/endpoint_test.go`
- Create: `apps/agent/internal/domain/policy/defaults_test.go`
- Create: `apps/agent/internal/adapters/policy/document.go`
- Create: `apps/agent/internal/adapters/policy/document_test.go`
- Create: `apps/agent/internal/adapters/policy/protobuf.go`
- Modify: `apps/agent/internal/adapters/contracts/policy.go`
- Modify: `apps/agent/internal/adapters/contracts/policy_test.go`
- Modify: all Agent files importing `packages/policy`
- Delete: `packages/policy/model.go`
- Delete: `packages/policy/model_test.go`

**Interfaces:**
- Consumes: 现有 `domain/policy.CollectionPolicy`、`domain/response.Policy` 和 Protobuf `policyv1`。
- Produces: `policy.Policy`、`policy.EndpointPolicy`、`policy.Normalize`、`policy.DefaultPolicy`、`policy.DefaultManagedPolicy`、`policy.DefaultDetectionPolicy` 与 Adapter `DecodePolicyDocument`、`EncodePolicyDocument`、`DetectionProto` mapper。

- [ ] **Step 1: 写 Policy Domain 失败测试**

测试必须直接构造 Domain 类型，不经过 Adapter：

```go
func TestDefaultPolicyBuildsObserveOnlyEndpointPolicy(t *testing.T) {
    value := DefaultPolicy("tenant-a")
    endpoint := value.EndpointPolicy()
    if endpoint.PolicyID != DefaultPolicyID || endpoint.Version != DefaultPolicyVersion {
        t.Fatalf("endpoint identity = %s@%d", endpoint.PolicyID, endpoint.Version)
    }
    if endpoint.Detection.Mode != "observe" || !endpoint.Collection.ObserveOnly {
        t.Fatalf("endpoint is not observe-only: %+v", endpoint)
    }
    if endpoint.Response.AllowedModes[0] != response.ModeObserve {
        t.Fatalf("response mode = %q", endpoint.Response.AllowedModes[0])
    }
}

func TestNormalizeDetectionDefaultsRuleSetVersions(t *testing.T) {
    enabled := true
    value := NormalizeDetection(DetectionPolicy{RuleSets: []RuleSetRef{{Ref: "ruleset:a", Enabled: &enabled}}})
    if value.PolicyID != "default-endpoint-detection" || value.Version != 1 || value.RuleSets[0].Version != "latest" {
        t.Fatalf("normalized detection = %+v", value)
    }
}
```

- [ ] **Step 2: 运行 Domain 测试并确认 RED**

Run:

```bash
go test ./apps/agent/internal/domain/policy -run 'Test(DefaultPolicy|NormalizeDetection)' -count=1
```

Expected: FAIL，原因是统一 Policy/Endpoint/Detection 类型或函数尚未定义。

- [ ] **Step 3: 实现最小纯 Domain 模型**

`endpoint.go` 的核心类型不得带 JSON tag 或 Protobuf 字段：

```go
type Policy struct {
    PolicyID string
    Version uint64
    TenantID string
    Scope ScopeSelector
    Detection *DetectionPolicy
    Telemetry *TelemetryPolicy
    Collection *CollectionPolicy
    EndpointRules []string
    CloudRules []string
    Mode string
    Converge *ConvergeParams
    Rarity *RarityParams
    Response response.Policy
    Published bool
    CreatedAt time.Time
    UpdatedAt time.Time
}

type EndpointPolicy struct {
    PolicyID string
    Version uint64
    Collection CollectionPolicy
    Detection DetectionPolicy
    Telemetry TelemetryPolicy
    Response response.Policy
}
```

`ConvergeParams` 与 `RarityParams` 必须是 Domain-owned 类型；`Policy` 中的 nil 表示未提供，Protobuf message 的构造与复制由 Adapter mapper 承担。原 `ManagerDefaultPolicy` 只被 Agent managed 测试支撑路径使用，迁移时改名为准确表达运行模式的 `DefaultManagedPolicy`，不得保留旧名 alias。

- [ ] **Step 4: 运行 Domain 测试并确认 GREEN**

Run:

```bash
go test ./apps/agent/internal/domain/policy ./apps/agent/internal/domain/response -count=1
```

Expected: PASS。

- [ ] **Step 5: 写 JSON 与 Protobuf Adapter 失败测试**

覆盖 wire 字段兼容、Collection 两种 behaviors 形态和 Detection 参数映射：

```go
func TestPolicyDocumentRoundTripPreservesPublishedContract(t *testing.T) {
    input := []byte(`{"policy_id":"p1","version":7,"tenant_id":"t1","mode":"observe","published":true,"telemetry":{"max_batch_items":256}}`)
    decoded, err := DecodePolicyDocument(input)
    if err != nil { t.Fatal(err) }
    output, err := EncodePolicyDocument(decoded)
    if err != nil { t.Fatal(err) }
    var document map[string]json.RawMessage
    if err := json.Unmarshal(output, &document); err != nil { t.Fatal(err) }
    if _, ok := document["telemetry"]; !ok { t.Fatal("missing telemetry") }
    if _, legacy := document["data_plane"]; legacy { t.Fatal("legacy data_plane emitted") }
}
```

- [ ] **Step 6: 运行 Adapter 测试并确认 RED**

Run:

```bash
go test ./apps/agent/internal/adapters/policy ./apps/agent/internal/adapters/contracts -count=1
```

Expected: FAIL，原因是 `DecodePolicyDocument`、`EncodePolicyDocument` 或 Domain-only mapper 尚未实现。

- [ ] **Step 7: 实现显式 wire mapper 并切换全部 Policy 调用方**

`document.go` 定义带 JSON tag 的私有 wire struct，`protobuf.go` 负责 `policyv1` 双向转换。将所有 Agent 生产与测试 import 切换到 `apps/agent/internal/domain/policy`；Adapter 只在边界调用 `DecodePolicyDocument`、`EncodePolicyDocument`、`DetectionProto`。删除 `adapters/contracts/policy.go` 中的 `DomainCollectionPolicy` 与 `SharedCollectionPolicy`，让 Collection Adapter 直接使用 Domain 类型。

- [ ] **Step 8: 运行 Policy 迁移测试并确认 GREEN**

Run:

```bash
go test ./apps/agent/internal/domain/policy/... ./apps/agent/internal/adapters/policy/... ./apps/agent/internal/adapters/contracts/... ./apps/agent/internal/application/policy/... ./apps/agent/internal/bootstrap/runtime/... -count=1
```

Expected: PASS，且：

```bash
rg -n 'packages/policy' apps/agent --glob '*.go'
```

Expected: 无输出。

- [ ] **Step 9: 删除旧 Policy 包并提交**

```bash
git rm packages/policy/model.go packages/policy/model_test.go
git add apps/agent/internal/domain/policy apps/agent/internal/adapters apps/agent/internal/bootstrap apps/agent/internal/application test
git commit -m "refactor(agent): move policy model into agent domain"
```

### Task 3: 将 Response 完整迁入 Agent Domain 与 Adapter

**Files:**
- Modify: `apps/agent/internal/domain/response/model.go`
- Create: `apps/agent/internal/domain/response/approval.go`
- Modify: `apps/agent/internal/domain/response/model_test.go`
- Create: `apps/agent/internal/domain/response/approval_test.go`
- Create: `apps/agent/internal/adapters/contracts/response.go`
- Create: `apps/agent/internal/adapters/contracts/response_test.go`
- Modify: `apps/agent/internal/adapters/inbound/grpc/codec.go`
- Modify: `apps/agent/internal/adapters/policy/endpoint.go`
- Modify: `apps/agent/internal/bootstrap/runtime/response_runtime.go`
- Modify: corresponding tests importing `packages/response`
- Delete: `packages/response/model.go`
- Delete: `packages/response/model_test.go`

**Interfaces:**
- Consumes: `domain/response.Command`、`Policy`、`Decision` 与现有 Control Protobuf。
- Produces: `DefaultPolicy`、`ApplyPolicyRequirements`、`ApprovalThreshold`、`ApprovalRoleAllowed`、`ApprovalCount`、`ApprovalSatisfied` 以及 JSON wire mapper。

- [ ] **Step 1: 写 Response 行为失败测试**

```go
func TestApplyPolicyRequirementsCopiesApprovalContract(t *testing.T) {
    command := ApplyPolicyRequirements(Command{}, Policy{
        ApprovalRequired: true, ApprovalThreshold: 2, ApprovalRoles: []string{"operator"},
    })
    if !command.ApprovalRequired || command.ApprovalThreshold != 2 || command.ApprovalRoles[0] != "operator" {
        t.Fatalf("command = %+v", command)
    }
}

func TestApprovalCountDeduplicatesActorsAndAllowsAdmin(t *testing.T) {
    command := Command{ApprovalRoles: []string{"operator"}, Approvals: []Approval{
        {Actor: "alice", Role: "operator", Approved: true},
        {Actor: "alice", Role: "operator", Approved: true},
        {Actor: "root", Role: "admin", Approved: true},
    }}
    if got := ApprovalCount(command); got != 2 { t.Fatalf("count = %d", got) }
}
```

- [ ] **Step 2: 运行 Response Domain 测试并确认 RED**

Run:

```bash
go test ./apps/agent/internal/domain/response -run 'Test(ApplyPolicyRequirements|ApprovalCount)' -count=1
```

Expected: FAIL，原因是完整审批 API 尚未存在，而非测试语法错误。

- [ ] **Step 3: 实现最小审批与默认策略行为**

复用 `Authorize` 已有的 mode/action/scope/binding 规则；`approval.go` 只承载策略要求、阈值、角色判断和 actor 去重。Domain 类型使用 `Mode`，不得导入 `sensor-sdk/contract`、JSON 或 Protobuf。

- [ ] **Step 4: 运行 Response Domain 测试并确认 GREEN**

Run:

```bash
go test ./apps/agent/internal/domain/response -count=1
```

Expected: PASS。

- [ ] **Step 5: 写 Response JSON mapper 失败测试**

```go
func TestDecodeResponseCommandPreservesPublishedFields(t *testing.T) {
    input := []byte(`{"response_id":"r1","tenant_id":"t1","agent_id":"a1","policy_id":"p1","policy_version":3,"action":"collect","mode":"observe","status":"pending","approvals":[{"actor":"alice","role":"operator","approved":true}]}`)
    command, err := DecodeResponseCommand(input)
    if err != nil { t.Fatal(err) }
    if command.ID != "r1" || command.PolicyVersion != 3 || len(command.Approvals) != 1 {
        t.Fatalf("command = %+v", command)
    }
}
```

- [ ] **Step 6: 运行 mapper 测试并确认 RED**

Run:

```bash
go test ./apps/agent/internal/adapters/contracts -run Response -count=1
```

Expected: FAIL，原因是 Response JSON mapper 尚未定义。

- [ ] **Step 7: 实现 mapper 并切换 Response 调用方**

在 `adapters/contracts/response.go` 定义私有 JSON wire 类型和 `DecodeResponseCommand`；gRPC raw JSON 只调用该 mapper，typed Protobuf 路径直接显式构造 Domain Command。Endpoint policy mapper 和 runtime context 直接接收 `domain/response.Policy`，删除 shared-to-domain 中转函数。

- [ ] **Step 8: 验证 Response 迁移并删除旧包**

Run:

```bash
go test ./apps/agent/internal/domain/response ./apps/agent/internal/adapters/contracts ./apps/agent/internal/adapters/inbound/grpc ./apps/agent/internal/adapters/policy ./apps/agent/internal/bootstrap/runtime -count=1
rg -n 'packages/response' apps/agent --glob '*.go'
```

Expected: 全部测试 PASS，`rg` 无输出。随后：

```bash
git rm packages/response/model.go packages/response/model_test.go
git add apps/agent/internal/domain/response apps/agent/internal/adapters apps/agent/internal/bootstrap
git commit -m "refactor(agent): move response model into agent domain"
```

### Task 4: 删除 Eventmodel 并收紧 Packages 治理

**Files:**
- Delete: `packages/eventmodel/behavior.go`
- Modify: `packages/README.md`
- Modify: `test/contracts/test_layered_architecture.py`
- Modify: `test/contracts/test_monorepo_layout.py`

**Interfaces:**
- Consumes: Task 2、Task 3 已完成的零旧 import 状态。
- Produces: 只允许真实跨产品契约进入 `packages/` 的文档与可执行白名单。

- [ ] **Step 1: 确认 Eventmodel 无消费者**

Run:

```bash
rg -n 'packages/eventmodel|eventmodel\.' --glob '*.go' --glob '*.md' --glob '*.py' .
```

Expected: 除 Task 11 架构合同和设计/计划文档外无生产或测试消费者。

- [ ] **Step 2: 删除 Eventmodel 并更新治理文档**

```bash
git rm packages/eventmodel/behavior.go
```

将 `packages/README.md` 的“Policy、Event、Response”泛化准入示例删除，明确：

```markdown
当前 `contracts/controlmodel` 由 Agent SQLite 与 Manager PostgreSQL 共同消费，`contracts/health` 由 Agent Runtime 与 Manager HTTP/identity 共同消费，因此二者属于跨产品稳定契约。只有单一 Agent 消费者的 Policy、Event、Response 业务模型必须保留在 `apps/agent/internal/domain`；不得用 alias、forwarding package 或兼容 facade 维持旧共享路径。
```

- [ ] **Step 3: 运行架构合同并确认 GREEN**

Run:

```bash
python3 -m unittest test.contracts.test_monorepo_layout test.contracts.test_layered_architecture
```

Expected: PASS。

- [ ] **Step 4: 扫描跨产品合同真实消费者**

Run:

```bash
rg -l 'packages/contracts/controlmodel' apps/agent apps/manager --glob '*.go'
rg -l 'packages/contracts/health' apps/agent apps/manager --glob '*.go'
```

Expected: 两条命令都同时列出 Agent 与 Manager 文件。

- [ ] **Step 5: 提交删除与治理收口**

```bash
git add packages/README.md test/contracts/test_layered_architecture.py test/contracts/test_monorepo_layout.py
git commit -m "refactor(packages): retire agent-owned shared models"
```

### Task 5: Task 11 最终质量门禁与审查

**Files:**
- Modify only if a failing acceptance test exposes a Task 11 regression.

**Interfaces:**
- Consumes: Tasks 1-4 的全部原子提交。
- Produces: 可关闭 Task 11 的测试证据、零旧路径扫描和干净工作树。

- [ ] **Step 1: 运行旧路径与边界静态扫描**

Run:

```bash
rg -n 'packages/(policy|response|eventmodel)' --glob '*.go' .
rg -n 'contracts/proto|sensor-sdk/contract|encoding/json|database/sql' apps/agent/internal/domain/policy apps/agent/internal/domain/response --glob '*.go'
find apps/agent/internal/domain/policy apps/agent/internal/domain/response -name '*.go' -exec wc -l {} +
```

Expected: 前两条无输出；所有文件不超过 500 行。人工检查本任务新增/修改函数均不超过 50 行。

- [ ] **Step 2: 运行 Agent 与 Manager 单元/集成测试**

Run:

```bash
go test ./apps/agent/... ./apps/manager/... -count=1
```

Expected: PASS。

- [ ] **Step 3: 运行竞态与静态检查**

Run:

```bash
go test -race ./apps/agent/... ./apps/manager/... -count=1
go vet ./apps/agent/... ./apps/manager/...
```

Expected: PASS，无竞态、vet error 或 warning。

- [ ] **Step 4: 运行架构合同与项目验收目标**

Run:

```bash
python3 -m unittest test.contracts.test_monorepo_layout test.contracts.test_layered_architecture
make test-functional DOMAIN=endpoint
make test-functional DOMAIN=topology
make test-detection
```

Expected: 合同、standalone endpoint、managed topology 与 Detection 矩阵全部 PASS。

- [ ] **Step 5: 检查 diff 与提交边界**

Run:

```bash
git diff --check
git status --short
git log --oneline --decorate -8
```

Expected: `git diff --check` 无输出，工作树无未提交文件，提交分别覆盖架构合同、Policy、Response、Eventmodel/治理四个关注点。

- [ ] **Step 6: 完整代码审查**

逐项确认：行为兼容、错误显式、依赖方向、无双路径、无 alias/facade、测试覆盖和文件/函数尺寸。Critical 与 Important finding 必须为零；发现问题时先写能复现的失败测试，再修复并重跑受影响门禁。
