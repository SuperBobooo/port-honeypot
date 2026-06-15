# 轻量跨平台端口蜜罐

这是一个面向企业实训任务书的 CS 架构低交互端口蜜罐项目。

项目包含：

- Rust 客户端节点：监听诱捕端口、记录访问、加密上报、断线补发、心跳保活。
- Python 服务端管理台：加密 TCP 接入、SQLite 存储、节点管理、日志检索、统计图表、多通道告警、异常探测告警、客户端配置包生成。
- Windows 客户端桌面控制器：配置编辑、启动/停止、状态查看、日志查看、自启动和托盘菜单。
- 离线优先设计：服务端只依赖 Python 标准库，数据库使用 SQLite，本地内网可直接运行。
- 文档与测试：系统设计、部署手册、开发指南、测试方案、实训报告模板。

## 快速启动服务端

```powershell
python -m server.porthoneypot --init-config
python -m server.porthoneypot
```

默认 Web 管理台：

```text
http://127.0.0.1:8088
```

默认加密 TCP 接入端口：

```text
0.0.0.0:9443
```

首次运行会生成：

```text
data/server_config.json
data/honeypot.db
data/packages/
logs/server.log
```

客户端与服务端日志都支持按大小自动轮转，默认 2MB、保留 5 份备份。

## 客户端

客户端源码位于 `client/`，按 Rust 单二进制交付方式组织：

```powershell
cd client
cargo build --release
```

若本机未安装 Rust，可先安装 Rust 工具链后再执行：

```powershell
rustup target add x86_64-pc-windows-msvc x86_64-unknown-linux-gnu aarch64-unknown-linux-gnu
python tools/build_clients.py --all
```

服务端 Web 管理台也提供“客户端生成”入口，会生成包含内置配置、使用说明和可选预编译二进制的离线分发包。

常用客户端命令：

```powershell
.\porthoneypot-client.exe run
.\porthoneypot-client.exe status
.\porthoneypot-client.exe check-update
.\porthoneypot-client.exe install-autostart
.\porthoneypot-client.exe uninstall-autostart
```

Windows 下 `install-autostart` 会注册 `PortHoneypotClient` 登录自启动计划任务。

## 远程节点控制

管理台的“节点状态与控制”支持：

- 启动节点全部监听任务。
- 停止节点全部监听任务。
- 修改节点监听端口列表，并通过心跳下发后实时生效。

该能力由服务端 `node_commands` 队列和客户端心跳拉取命令实现。

## Windows 托盘控制

完整桌面管理端：

```powershell
python tools\desktop_gui.py
```

桌面 GUI 会启动本地服务端，并提供总览统计、节点管理、攻击日志查询、服务控制、客户端生成、更新发布和服务端日志查看。

服务端提供一个免安装托盘控制器：

```powershell
powershell -ExecutionPolicy Bypass -File tools\windows_tray.ps1
```

托盘菜单支持打开管理台、启动服务端进程、启动/停止 TCP 服务、测试告警、停止声音和退出托盘。

Windows 客户端捕获访问或检测到服务端断连时，会触发本地声音提示和托盘气泡通知。

Windows 客户端桌面控制器：

```powershell
powershell -ExecutionPolicy Bypass -File tools\client_gui.ps1
```

该工具支持打开/隐藏主界面、启动/停止客户端、编辑 `client_config.json`、查看客户端日志、安装/卸载自启动，并常驻系统托盘。

## 自动更新

构建并发布 Windows 客户端更新：

```powershell
python tools\build_clients.py --target windows-x64 --server-host 127.0.0.1
python tools\publish_update.py --platform windows-x64 --version 0.1.1 --notes "update notes"
```

客户端配置中 `update_enabled=true` 且 `update_base_url` 指向管理台地址时，会定期检查：

```text
http://<server-web-host>:8088/api/client-updates/windows-x64/manifest
```

发现更高版本后会下载二进制、校验 SHA256，并在 Windows 上通过延迟 PowerShell 脚本替换自身后重启。

## 项目结构

```text
client/                  Rust 客户端源码
server/porthoneypot/     Python 服务端源码
tools/                   构建、烟测工具
tests/                   Python 单元测试
docs/                    设计、部署、开发、测试与实训文档
```

## 说明

一般 TCP 诱捕模式完整可运行。Linux 隐身 SYN 捕获 PoC 已实现，配合 `scripts/linux_stealth_setup.sh` 可阻断 RST 并捕获 SYN 探测。Windows 生产级隐身模式仍需 WinDivert/NDIS 驱动。详见 `docs/linux_stealth_poc.md`、`docs/system_design.md` 与 `docs/deployment_guide.md`。

## 验证

```powershell
python -m unittest discover -s tests -p "test_*.py"
python tools\smoke_test.py
python tools\rust_client_integration.py
```
