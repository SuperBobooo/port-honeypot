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

异常端口探测告警：

1. 将 `alerts.abnormal_probe_window_seconds` 设置为 120。
2. 将 `alerts.abnormal_probe_distinct_ports` 设置为 4，`alerts.abnormal_probe_min_events` 设置为 6。
3. 使用同一源 IP 在 120 秒内访问 6 次以上，目标端口覆盖至少 4 个不同端口。
4. 服务端日志和告警历史应出现 `abnormal_probe` 对应告警记录。

日志轮转：

1. 将服务端 `log_max_bytes` 或客户端 `log_max_bytes` 临时调小。
2. 连续产生运行日志。
3. 确认 `logs/server.log.1` 或 `logs/client.log.1` 生成，新日志继续写入原始日志文件。

远程控制：

1. 客户端上线后，在管理台节点行点击“改端口”。
2. 输入新端口列表。
3. 等待下一次心跳。
4. 访问新增端口应产生攻击日志，访问已移除端口应失败。

Windows 托盘与本地通知：

1. 运行 `python tools\desktop_gui.py`。
2. 确认桌面 GUI 能显示统计、节点、日志和服务端日志。
3. 在桌面 GUI 中点击“测试告警”，确认声音或提示触发。
4. 关闭窗口时确认出现退出二次确认。

服务端托盘控制器：

1. 运行 `powershell -ExecutionPolicy Bypass -File tools\windows_tray.ps1`。
2. 右键托盘图标，点击“Start server process”。
3. 点击“Open dashboard”，确认管理台打开。
4. 点击“Test alert”，确认托盘气泡提示出现。
5. 启动客户端并访问诱捕端口，确认客户端本地声音和气泡通知触发。

客户端桌面 GUI 与托盘：

1. 运行 `powershell -ExecutionPolicy Bypass -File tools\client_gui.ps1`。
2. 在 Config 页编辑服务端地址、监听端口和日志轮转参数，点击 “Save config”。
3. 点击 “Start client” 启动客户端，确认状态显示 Running。
4. 点击 “Hide to tray” 后双击托盘图标，确认主界面可重新打开。
5. 点击 “Install autostart” 和 “Uninstall autostart”，确认命令输出无错误。
6. 关闭窗口时应隐藏到托盘；托盘菜单 Exit 应出现退出确认。

Windows 隐身模式：

1. 确认客户端运行目录包含 `porthoneypot-client.exe`、`WinDivert.dll`、`WinDivert64.sys` 和 `client_config.json`。
2. 在 `client_config.json` 设置 `stealth_mode=true`、`stealth_fallback_to_tcp=false`、`listen_ports=[22,80,3389]`。
3. 使用管理员 PowerShell 执行 `.\porthoneypot-client.exe run`。
4. 从另一台机器执行 `nmap -sS -Pn -p 22,80,3389 <windows-client-ip>`。
5. 扫描端应表现为 `filtered` 或无响应，服务端管理台应出现 `mode=stealth` 的 SYN 探测日志。

自动更新：

1. 运行 `python tools\build_clients.py --target windows-x64 --server-host 127.0.0.1`。
2. 运行 `python tools\publish_update.py --platform windows-x64 --version 0.1.1`。
3. 确认 `data/updates/windows-x64/manifest.json` 存在。
4. 运行 `python tools\rust_client_integration.py`，脚本会验证客户端 `check-update` 可读取 manifest。

Linux 隐身模式 PoC：

1. 在 Linux 节点准备 `client_config.json`，设置 `stealth_mode=true`、`stealth_fallback_to_tcp=false`。
2. 执行 `sudo scripts/linux_stealth_setup.sh setup 22,80,3389`。
3. 执行 `sudo ./porthoneypot-client run`。
4. 从另一台主机执行 `nmap -sS -Pn -p 22,80,3389 <client-ip>`。
5. 服务端管理台应出现 `mode=stealth` 的 SYN 探测日志。
6. 执行 `sudo scripts/linux_stealth_setup.sh cleanup 22,80,3389` 清理规则。

## 4. 兼容性矩阵

| 平台 | 服务端 | 客户端普通模式 | 客户端隐身模式 |
| --- | --- | --- | --- |
| Windows 10/11 x64 | 支持 Python 3.8+ 时可运行 | 支持 | WinDivert 后端，需管理员权限 |
| Windows 7+ / Windows Server 2008+ x64 | 支持 Python 3.8+ 时可运行 | Rust 目标支持后可运行 | 需实机验证 WinDivert 驱动兼容性 |
| Debian/CentOS x64 | 支持 | 支持 | 需 root + raw socket + RST 阻断 |
| 统信 UOS/银河麒麟 x64/arm64 | 支持 | 支持 | 需 root + 系统防火墙规则 |
| macOS 10.15+ | 支持 | 支持 | 需 BPF/pf 后端 |

## 5. 已知限制

- 当前仓库没有附带预编译二进制，需本机安装 Rust 后构建。
- Linux 隐身 SYN 捕获 PoC 已实现，但仍需在真实 Linux/信创系统上完成 raw socket 与 RST 阻断实机验收。
- Windows 隐身模式已接入 WinDivert 后端，但 Windows 7/Server 2008 驱动兼容性仍需单独实机验证。
