# Manager Ports

Manager 面向外部能力定义的消费者接口。仅允许依赖本产品 `domain`、`ports` 和 Go 标准库；禁止反向依赖 Application、Adapters、Bootstrap 或具体基础设施。

规则来源：[分层架构设计](../../../../../docs/superpowers/specs/2026-08-08-domain-application-ports-adapters-architecture-design.md)。
