# 开发指南

## 1. 开发环境

服务端：

```powershell
python --version
python -m server.porthoneypot --init-config
python -m server.porthoneypot
```

客户端：

```powershell
rustc --version
cargo --version
cd client
cargo build
```

## 2. 服务端模块

- `config.py`：配置结构、默认配置生成。
- `crypto.py`：加密帧实现。
- `protocol.py`：长度前缀帧读写。
- `database.py`：SQLite schema 与查询接口。
- `tcp_service.py`：客户端接入和消息处理。
- `alerts.py`：多通道告警、限频和异常端口探测规则。
- `web_service.py`：Web UI 和 HTTP API。
- `client_builder.py`：客户端分发包生成。
- `update_manager.py`：客户端更新包发布、manifest 生成、二进制下载。
- `desktop_app.py`：tkinter 桌面管理端，复用服务端核心应用对象。
- `app.py`：应用生命周期管理。
- `tools/windows_tray.ps1`：服务端 Windows 免安装托盘控制器，使用 .NET WinForms NotifyIcon。
- `tools/client_gui.ps1`：客户端 Windows 桌面控制器，提供配置、启动/停止、日志查看、自启动和托盘菜单。

## 3. 客户端模块

当前客户端保持单文件主程序，便于实训阅读和跨平台编译。后续可按以下方向拆分：

- `config`：配置与 node_id 管理。
- `crypto`：协议加密。
- `listener`：普通 TCP 监听。
- `stealth`：平台隐身后端。
- `spool`：本地队列和断线补发。
- `transport`：服务端连接、心跳、上传。
- `system`：自启动、托盘、弹窗、声音、日志轮转。

当前客户端已实现一个轻量 `ListenerManager`，负责运行时启动、停止和替换端口监听。服务端下发的节点命令会在心跳响应中返回，客户端收到后立即应用。

客户端日志轮转由 `log_max_bytes` 和 `log_backup_count` 控制，默认 2MB、保留 5 份备份。服务端文件日志使用同名配置项，写入 `logs/server.log`，同时仍保留 SQLite `server_logs` 表供管理台查询。

## 4. 协议扩展

新增消息类型时，需要同时修改：

- Rust 客户端发送/接收逻辑。
- Python `tcp_service.py` 消息分发。
- 必要时扩展数据库表或 Web API。

建议保持消息为 JSON 对象，并包含 `type` 字段。

服务端下发命令结构：

```json
{
  "id": 1,
  "command": "set_ports",
  "payload": {
    "listen_ports": [22, 80, 3389]
  }
}
```

## 7. 自动更新扩展

客户端更新配置：

- `update_enabled`：是否启用后台自动更新。
- `update_interval_secs`：检查间隔，客户端最小按 30 秒处理。
- `update_base_url`：服务端管理台地址，例如 `http://127.0.0.1:8088`。

更新 manifest 接口：

```text
GET /api/client-updates/<platform>/manifest
GET /api/client-updates/<platform>/download
```

发布接口：

```text
POST /api/client-updates/publish
```

发布脚本：

```powershell
python tools\publish_update.py --platform windows-x64 --version 0.1.1
```

## 5. 平台后端扩展

隐身模式生产化建议：

- Linux：raw socket 或 AF_PACKET 捕获 SYN，iptables/nftables 阻断 RST。
- Windows：WinDivert 捕获和阻断，或 NDIS 过滤驱动。
- macOS：BPF/pf 组合。

托盘与本地通知建议：

- Windows：Shell_NotifyIcon + Win32 消息循环。
- Linux：AppIndicator/libnotify 或后台 daemon 日志方式。
- macOS：NSUserNotification 或菜单栏应用。

## 6. 代码规范

- 服务端不引入公网依赖，保证内网离线可部署。
- 客户端保持低资源占用，避免引入大型运行时。
- 所有网络输入都必须限制长度，当前协议最大帧为 8MB，客户端访问内容最多 1KB。
- 新增存储字段时同步更新查询索引，避免日志量增大后管理台卡顿。
