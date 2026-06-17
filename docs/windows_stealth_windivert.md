# Windows 隐身模式 WinDivert 后端

Windows 隐身模式通过 WinDivert 在用户态截获入站 SYN 包，实现“不绑定端口、不完成 TCP 握手、不让内核回复 RST”的虚拟监听行为。

## 1. 运行时文件

Windows x64 客户端运行目录需要包含：

```text
porthoneypot-client.exe
WinDivert.dll
WinDivert64.sys
client_config.json
```

`tools/build_clients.py --target windows-x64` 会在 `third_party/WinDivert-2.2.2-A/` 存在时自动复制 `WinDivert.dll` 和 `WinDivert64.sys` 到 `dist/client-bin/windows-x64/`。

## 2. 权限要求

必须使用管理员权限运行客户端，否则 WinDivert 驱动无法打开。

```powershell
# 管理员 PowerShell
.\porthoneypot-client.exe run
```

客户端 GUI 也需要以管理员 PowerShell 启动，才能成功启动隐身客户端：

```powershell
powershell -ExecutionPolicy Bypass -File tools\client_gui.ps1
```

## 3. 客户端配置

严格隐身测试建议关闭普通 TCP 降级：

```json
{
  "listen_ports": [22, 80, 3389],
  "stealth_mode": true,
  "stealth_fallback_to_tcp": false
}
```

如果 `stealth_fallback_to_tcp=true`，当 WinDivert DLL 缺失、驱动无法加载或权限不足时，客户端会降级为普通 TCP 蜜罐，便于实训演示继续运行。

## 4. 工作机制

WinDivert 过滤器捕获：

```text
inbound and !impostor and ip and tcp.Syn and !tcp.Ack
```

客户端在用户态解析 IPv4/TCP 包：

- 目标端口在 `listen_ports` 内：记录 `mode=stealth` 攻击事件，不重注入数据包，等价于丢弃 SYN。
- 目标端口不在 `listen_ports` 内：调用 `WinDivertSend` 立即重注入，避免影响本机正常服务。

## 5. 验证方法

在 Windows 测试机管理员运行客户端后，从另一台机器执行：

```bash
nmap -sS -Pn -p 22,80,3389 <windows-client-ip>
```

预期：

- 扫描端通常看到 `filtered` 或无响应。
- Windows 客户端不建立 TCP 握手。
- 服务端管理台出现 `mode=stealth` 的 SYN 探测日志。
- 客户端 `logs/client.log` 出现 WinDivert stealth backend started 相关日志。

## 6. 注意事项

- 该模式会丢弃配置端口的入站 SYN。如果测试机真实运行了 22/80/3389 服务，这些服务会在隐身模式期间不可连接。
- 当前实现覆盖 IPv4/TCP SYN；IPv6 可作为后续增强。
- WinDivert 官方包采用 LGPLv3/GPLv2 双许可证，项目交付时应保留 WinDivert 原始 LICENSE 文件或在文档中注明来源。
