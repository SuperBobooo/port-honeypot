# Linux 隐身模式 PoC

本 PoC 实现任务书中的隐身监听核心行为：

- 不绑定 TCP 监听端口。
- 不完成 TCP 握手。
- 通过 raw TCP socket 捕获 IPv4/TCP SYN 探测包。
- 通过防火墙规则阻断系统自动发出的 RST。
- 将 SYN 探测记录为 `mode=stealth` 攻击事件并加密上报服务端。

## 1. 适用范围

支持 Linux x86_64/arm64，包括 Debian、Ubuntu、CentOS、统信 UOS、银河麒麟等发行版。需要 root 权限或 `CAP_NET_RAW` 能力。

Windows 隐身模式需要 WinDivert/NDIS 驱动，不在本 PoC 范围内。

## 2. 准备客户端配置

客户端配置中启用隐身模式，并建议关闭普通 TCP 降级：

```json
{
  "listen_ports": [22, 80, 3389],
  "stealth_mode": true,
  "stealth_fallback_to_tcp": false
}
```

如果保留 `stealth_fallback_to_tcp=true`，当 raw socket 权限不足时客户端会降级为普通 TCP 蜜罐。

## 3. 设置 RST 阻断

在 Linux 节点上执行：

```bash
sudo scripts/linux_stealth_setup.sh setup 22,80,3389
```

查看规则：

```bash
sudo scripts/linux_stealth_setup.sh status
```

清理规则：

```bash
sudo scripts/linux_stealth_setup.sh cleanup 22,80,3389
```

脚本优先使用 `iptables`，没有 `iptables` 时使用 `nftables`。

## 4. 运行客户端

方式一，直接 root 运行：

```bash
sudo ./porthoneypot-client run
```

方式二，仅授予 raw socket 能力：

```bash
sudo setcap cap_net_raw+ep ./porthoneypot-client
./porthoneypot-client run
```

## 5. 验证

从另一台机器扫描：

```bash
nmap -sS -Pn -p 22,80,3389 <client-ip>
```

预期：

- 客户端不会建立 TCP 握手。
- 扫描端看到端口通常表现为 `filtered` 或无响应。
- 服务端管理台出现 `mode=stealth` 的攻击日志。
- 内容片段类似：

```text
SYN probe to 192.168.1.20:3389 ttl=64 flags=0x02
```

## 6. 注意事项

- 必须先设置 RST 阻断，否则 Linux 内核可能自动回复 RST，使扫描方判断端口关闭。
- 当前 PoC 覆盖 IPv4/TCP SYN；IPv6 隐身监听可作为后续增强项。
- raw socket 捕获的是本机收到的 TCP 包，不会对攻击者回复任何应用层内容。
- 同一源 IP、源端口、目标端口 2 秒内的重复 SYN 会被去重，避免扫描重传导致大量重复日志。
- 实训环境建议使用虚拟机快照，测试后执行 cleanup 清理防火墙规则。
