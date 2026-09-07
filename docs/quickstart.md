# 快速开始

本教程在一台使用 systemd 的 x86_64 Linux 主机上安装 standalone Agent，并通过本地控制接口查看健康状态、Event 和 Signal。完成教程不需要管理平台。

## 前置条件

- Go 1.26 或更高版本；
- `make`、`curl` 和 root 权限；
- 可用的 Tetragon bundle；
- 支持 BTF 和 eBPF 的 Linux 内核。

如果目标是运行仓库测试而不是安装本机 Agent，先执行：

```bash
make test-doctor
```

## 安装 Agent

在仓库根目录执行：

```bash
make install-agent
```

安装程序会构建 Agent 和 `sysarmorctl`，安装默认 endpoint policy 和由 Agent 管理的 Tetragon，并启动 systemd 服务。

## 验证运行状态

```bash
sudo sysarmorctl agent health
sudo sysarmorctl agent capability
```

健康输出应包含 Agent 身份、sensor 状态、采集能力、telemetry 状态和当前策略信息。若命令无法连接，检查：

```bash
sudo systemctl status sysarmor-agent
sudo journalctl -u sysarmor-agent --no-pager -n 100
sudo test -S /run/sysarmor/agent/control.sock
```

## 查看 Event 和 Signal

打开两个终端分别观察本地流：

```bash
sudo sysarmorctl event watch --include-recent
sudo sysarmorctl signal watch --include-recent
```

在主机上执行普通进程、文件或网络操作。实际 Event 和 Signal 取决于当前 collection、detection 和 content。Signal 是结构化行为信号，不保证每个 Event 都产生 Signal，也不表示所有 Signal 都是恶意告警。

## 查看和解释策略

```bash
sudo sysarmorctl policy current
sudo sysarmorctl policy explain --file /etc/sysarmor/agent/policy.json
```

不要直接修改 SQLite 或本地 segment。控制 socket 是支持的本地操作边界。策略结构和四层语义见[策略指南](guides/policy.md)。

## 下一步

- 需要集中管理、查询和关联时，继续阅读 [Agent 管理](guides/agent-management.md)和[部署指南](operations/deployment.md)。
- 需要理解 Event、Signal、Evidence 和 Incident 时，阅读[检测概念](concepts/detection.md)和[调查指南](guides/investigation.md)。
- 需要删除本机安装时，先阅读[维护指南](operations/maintenance.md)，确认是否保留本地数据。
