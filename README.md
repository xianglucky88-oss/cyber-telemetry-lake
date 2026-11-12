# Cyber Telemetry Lake

将终端、网络、身份和云审计事件统一成可关联的安全遥测数据集。流水线保留原始事件的可追溯标识，处理重复、乱序时间和质量拒绝，并把短时间窗口内共享主体或资产的事件聚合为安全事件时间线。

## 运行

```bash
PYTHONPATH=src python3 -m cyber_telemetry.cli \
  --fixture fixtures/sample.json \
  --database /tmp/cyber-telemetry-lake.sqlite3
```

## 外部依赖类型与版本

- Python 3.11+
- SQLite 3.x
- pytest 8.3.x（测试）

仅使用 fixture 和本地数据库验证，不写入真实账号、token、连接串或密钥。

## 验证

```bash
PYTHONPATH=src python3 -m pytest --import-mode=importlib tests
PYTHONPATH=src python3 -m compileall -q src
```
