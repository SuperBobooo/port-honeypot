# 测试与兼容性文档

## 1. 单元测试

运行：

```powershell
python -m unittest discover -s tests -p "test_*.py"
```

覆盖点：

- 加密帧往返和篡改检测。
- 协议 socket 收发。
- SQLite 节点、事件、统计和内容解密。

## 2. 端到端烟测

运行：

```powershell
python tools/smoke_test.py
```

流程：

1. 临时生成服务端配置。
2. 启动 TCP 服务与 Web 服务。
3. 模拟客户端注册、心跳、上传访问事件。
4. 验证 SQLite 中事件数量。
5. 关闭服务。

真实 Rust 客户端联调：

```powershell
python tools/rust_client_integration.py
```

流程：

1. 启动临时服务端。
2. 写入临时客户端配置。
3. 启动 Windows x64 Rust 客户端二进制。
4. 访问客户端监听端口并确认事件入库。
5. 服务端下发 `stop_all` 命令。
6. 验证客户端监听端口停止接受连接。
7. 验证客户端 `check-update` 能读取服务端更新 manifest。

## 3. 手工测试用例

普通模式访问捕获：

1. 启动服务端。
2. 启动客户端并监听 8022。
3. 使用 `telnet <client-ip> 8022` 或 `nc <client-ip> 8022` 发送内容。
4. Web 管理台应出现攻击事件。

断线补发：

1. 启动客户端。
2. 停止服务端 TCP 服务。
3. 访问客户端监听端口。
4. 确认 `data/client_spool.jsonl` 增加事件。
5. 恢复服务端 TCP 服务。
6. 确认事件上传成功且队列清空。

告警限频：

1. 将 `alerts.rate_limit_seconds` 设置为 60。
2. 同一源 IP 连续访问同一节点同一端口。
3. 告警历史只应按限频间隔记录。

远程控制：

1. 客户端上线后，在管理台节点行点击“改端口”。
2. 输入新端口列表。
3. 等待下一次心跳。
4. 访问新增端口应产生攻击日志，访问已移除端口应失败。

Windows 托盘与本地通知：

1. 运行 `powershell -ExecutionPolicy Bypass -File tools\windows_tray.ps1`。
2. 右键托盘图标，点击“Start server process”。
3. 点击“Open dashboard”，确认管理台打开。
4. 点击“Test alert”，确认托盘气泡提示出现。
5. 启动客户端并访问诱捕端口，确认客户端本地声音和气泡通知触发。

自动更新：

1. 运行 `python tools\build_clients.py --target windows-x64 --server-host 127.0.0.1`。
2. 运行 `python tools\publish_update.py --platform windows-x64 --version 0.1.1`。
3. 确认 `data/updates/windows-x64/manifest.json` 存在。
4. 运行 `python tools\rust_client_integration.py`，脚本会验证客户端 `check-update` 可读取 manifest。

## 4. 兼容性矩阵

| 平台 | 服务端 | 客户端普通模式 | 客户端隐身模式 |
| --- | --- | --- | --- |
| Windows 7+ x64 | 支持 Python 3.8+ 时可运行 | Rust 目标支持后可运行 | 需 WinDivert/NDIS 后端 |
| Windows Server 2008+ x64 | 支持 Python 3.8+ 时可运行 | Rust 目标支持后可运行 | 需 WinDivert/NDIS 后端 |
| Debian/CentOS x64 | 支持 | 支持 | 需 root + raw socket + RST 阻断 |
| 统信 UOS/银河麒麟 x64/arm64 | 支持 | 支持 | 需 root + 系统防火墙规则 |
| macOS 10.15+ | 支持 | 支持 | 需 BPF/pf 后端 |

## 5. 已知限制

- 当前仓库没有附带预编译二进制，需本机安装 Rust 后构建。
- 隐身 SYN 捕获为平台特权能力，当前实现提供后端边界和降级策略。
- Windows 托盘图标、本地弹窗目前以服务端 Web 管理台和本地声音告警为主，生产化可按开发指南接入 Win32 托盘模块。
