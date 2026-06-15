# 部署与使用手册

## 1. 服务端部署

环境要求：

- Python 3.10+
- 无需外部数据库和第三方 Python 包

初始化配置：

```powershell
python -m server.porthoneypot --init-config
```

启动服务端：

```powershell
python -m server.porthoneypot
```

访问管理台：

```text
http://127.0.0.1:8088
```

配置文件：

```text
data/server_config.json
```

常用配置项：

- `shared_key_hex`：客户端与服务端共享密钥。
- `tcp.host` / `tcp.port`：客户端接入地址。
- `web.host` / `web.port`：Web 管理台地址。
- `alerts`：告警通道和限频。

## 2. 客户端配置包生成

进入 Web 管理台的“客户端生成”区域，填写：

- 服务端 IP。
- 服务端 TCP 端口。
- 默认监听端口列表。
- 是否默认启用隐身模式。
- 目标平台。

点击生成后，服务端会在 `data/packages/` 下生成 zip 包。

## 3. 客户端编译

安装 Rust 后执行：

```powershell
cd client
cargo build --release
```

批量构建：

```powershell
python tools/build_clients.py --all --server-host 192.168.1.10 --ports 21,22,23,80,445,3389
```

生成结果：

```text
dist/client-bin/windows-x64/porthoneypot-client.exe
dist/client-bin/linux-x64/porthoneypot-client
dist/client-bin/linux-arm64/porthoneypot-client
```

## 4. 客户端运行

普通运行：

```powershell
.\porthoneypot-client.exe
```

Linux：

```bash
chmod +x ./porthoneypot-client
./porthoneypot-client
```

客户端会自动创建：

```text
data/client_spool.jsonl
data/node_id
logs/client.log
```

客户端控制命令：

```powershell
.\porthoneypot-client.exe status
.\porthoneypot-client.exe check-update
.\porthoneypot-client.exe install-autostart
.\porthoneypot-client.exe uninstall-autostart
```

默认直接运行等价于：

```powershell
.\porthoneypot-client.exe run
```

## 5. 自启动建议

Windows 可通过计划任务或注册表启动项部署：

```powershell
.\porthoneypot-client.exe install-autostart
```

该命令会创建 `PortHoneypotClient` 计划任务，触发条件为当前用户登录。

Linux systemd 示例：

```ini
[Unit]
Description=Port Honeypot Client
After=network-online.target

[Service]
ExecStart=/opt/porthoneypot/porthoneypot-client
WorkingDirectory=/opt/porthoneypot
Restart=always

[Install]
WantedBy=multi-user.target
```

## 6. 隐身模式部署说明

隐身模式需要捕获 SYN 包且阻止系统自动回复 RST，必须具备管理员/root 权限。

Linux 可参考：

```bash
iptables -A OUTPUT -p tcp --sport 3389 --tcp-flags RST RST -j DROP
```

或使用 nftables 等价规则。

Windows 生产实现建议接入 WinDivert 或 NDIS 过滤驱动，用户态程序负责解析 SYN 并上报服务端。

当前客户端默认启用 `stealth_fallback_to_tcp`：隐身后端不可用时降级为普通 TCP 诱捕，保证实训环境可运行。

## 7. 告警配置

编辑 `data/server_config.json` 中的 `alerts`。

邮件：

```json
"email": {
  "enabled": true,
  "smtp_host": "smtp.example.com",
  "smtp_port": 465,
  "username": "user@example.com",
  "password": "password",
  "sender": "user@example.com",
  "receivers": ["secops@example.com"],
  "use_ssl": true
}
```

钉钉、飞书、企业微信填入对应机器人 Webhook 即可。钉钉如开启加签，将 secret 填入 `dingtalk.secret`。

## 8. 远程端口控制

启动服务端和客户端后，在管理台“节点状态与控制”中可以：

- 点击“启动”恢复节点监听。
- 点击“停止”停止节点所有监听。
- 点击“改端口”批量替换监听端口列表。

客户端通过心跳接收命令，默认几秒内生效。若节点离线，命令会保留在服务端队列中，待节点恢复心跳后下发。

## 9. Windows 托盘与本地通知

启动完整桌面管理端：

```powershell
python tools\desktop_gui.py
```

桌面管理端功能：

- 总览统计与 TOP 图表。
- 节点上线状态与远程启动 / 停止 / 改端口。
- 攻击日志筛选查询。
- TCP 服务启停、告警测试、停止声音。
- 客户端配置包生成。
- 客户端更新发布。
- 服务端日志查看。
- 退出二次确认。

启动服务端托盘控制器：

```powershell
powershell -ExecutionPolicy Bypass -File tools\windows_tray.ps1
```

托盘菜单功能：

- 打开 Web 管理台。
- 启动服务端后台进程。
- 启动 / 停止 TCP 接入服务。
- 发送测试告警。
- 停止当前报警声音。
- 退出托盘。

客户端在 Windows 上捕获端口访问或检测到服务端连接断开时，会调用系统托盘气泡通知并播放短促声音。

## 10. 自动更新

构建最新客户端：

```powershell
python tools\build_clients.py --target windows-x64 --server-host 192.168.1.10 --web-port 8088
```

发布为更新包：

```powershell
python tools\publish_update.py --platform windows-x64 --version 0.1.1 --notes "修复客户端并增强控制能力"
```

也可以在管理台“客户端自动更新”区域发布当前二进制。

客户端手动检查：

```powershell
.\porthoneypot-client.exe check-update
```

自动检查由配置项控制：

```json
{
  "update_enabled": true,
  "update_interval_secs": 300,
  "update_base_url": "http://192.168.1.10:8088"
}
```

Windows 客户端下载更新后会校验 SHA256，再创建 `updates/apply_update.ps1` 替换自身并重启。
