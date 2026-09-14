# Detector 平台方案 B 实施计划

目标：在现有三 Job 架构内逐步建立可测量、可回放、按需使用图能力的 Detector 平台。

已确认约束：Campaign/Terminal/ISG 属于 Nodlink；算法与 Kafka、Flink、OpenSearch 解耦；不预设动态连通分量或复杂缓存；性能优化保持现有检测语义。

## 首批交付

- [x] 在 `tests/test_detection_state.py` 验证逐 Detector diagnostics 和 analysis metrics 穿过批处理返回，且每批只计算一次。
- [x] 修改 `detection/state.py` 结果合同，向最后一条批处理结果附加分析指标；`jobs/detection.py` 输出独立 analysis metrics，保留窗口指标口径。
- [x] 在 `tests/test_nearest_hop.py` 对比旧算法，覆盖等长选路、不可达、路径深度和自节点；实现单次有界 BFS，保持目标 ID 决胜及邻接遍历顺序。
- [x] 修复 `tools/nodlink/replay.py` 的旧导入；增加使用生产 DetectionState 的通用规范化记录回放，不解析任何算法私有状态。验证租户隔离与配置校验；支持 Detector 名称列表，多算法效果矩阵仍待实测。
- [x] 运行领域测试、回放测试及差分验证，记录限制与结果。

验证命令：`PYTHONPATH=apps/streaming/src:apps/streaming python -m pytest -q apps/streaming/tests tools/nodlink/test_replay.py`。

## 后续独立交付

1. 实验 Detection Job 的 consumer group、输出与 checkpoint 隔离合同和部署验收。
2. Finding 更新/失效协议及查询投影，明确历史发现与当前有效结论。
3. 依据分段 profiling 优化事实淘汰、图更新、规则索引；由第二个实验 Detector 验证平台扩展性。

这些部分未完成前，不宣称方案 B 已全部交付。真实 Flink E2E 与离线回放分别报告，回放不证明 checkpoint 或背压性能。

## 首批验证记录

- streaming 全量测试：189 passed；旧 Nodlink 回放测试：4 passed。
- 独立审查发现回放策略校验缺口，已提取共享 policy validation 并补回归。
- 合成链图微基准：3,000 条边、128 个超深度目标；旧搜索 393.14 ms，新搜索 0.026 ms，结果相同。此极端局部案例不代表整机吞吐提升。
- 历史 processing_ms 采集为 max，不能称为总耗时或 Nodlink 独立耗时。
- `detection/state.py` 和 `jobs/detection.py` 原有文件均超过 500 行；已识别结果合同、窗口运行时、持久化三个拆分边界，首批仅提取共享策略校验，其余拆分随对应状态/运行时重构推进，避免混入无关改动。
- 本次未启动新 hybrid VM E2E，不报告生产性能已达标。
