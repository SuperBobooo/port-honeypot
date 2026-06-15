from __future__ import annotations

import json
import threading
import time
import urllib.parse
from http import HTTPStatus
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from typing import Any

from .alerts import AlertManager
from .client_builder import ClientBuilder, TARGETS
from .database import Database
from .tcp_service import TcpService
from .update_manager import UpdateManager


HTML = r"""<!doctype html>
<html lang="zh-CN">
<head>
  <meta charset="utf-8">
  <meta name="viewport" content="width=device-width, initial-scale=1">
  <title>轻量端口蜜罐管理台</title>
  <style>
    :root { --bg:#f5f7fb; --panel:#fff; --line:#d8dee9; --text:#18202f; --muted:#667085; --brand:#1664d9; --danger:#c2410c; --ok:#0f766e; }
    * { box-sizing: border-box; }
    body { margin: 0; font-family: "Segoe UI", "Microsoft YaHei", Arial, sans-serif; background: var(--bg); color: var(--text); }
    header { padding: 18px 28px; background: #111827; color: white; display: flex; align-items: center; justify-content: space-between; gap: 18px; }
    h1 { margin: 0; font-size: 20px; font-weight: 650; }
    main { padding: 22px 28px 36px; display: grid; gap: 18px; }
    section { background: var(--panel); border: 1px solid var(--line); border-radius: 8px; padding: 16px; }
    h2 { margin: 0 0 14px; font-size: 16px; }
    .grid { display: grid; grid-template-columns: repeat(4, minmax(0, 1fr)); gap: 12px; }
    .metric { border: 1px solid var(--line); border-radius: 8px; padding: 14px; background: #fbfcff; }
    .metric b { display: block; font-size: 26px; margin-bottom: 4px; }
    .muted { color: var(--muted); font-size: 13px; }
    table { width: 100%; border-collapse: collapse; font-size: 13px; }
    th, td { padding: 9px 8px; border-bottom: 1px solid var(--line); text-align: left; vertical-align: top; }
    th { color: var(--muted); font-weight: 600; }
    .pill { display: inline-flex; align-items:center; min-height:22px; padding: 2px 8px; border-radius: 999px; font-size: 12px; background:#edf2ff; color:#1d4ed8; }
    .online { background:#ecfdf5; color:#047857; }
    .offline { background:#fff7ed; color:#c2410c; }
    .row { display: flex; flex-wrap: wrap; gap: 10px; align-items: center; }
    input, select { border: 1px solid var(--line); border-radius: 6px; min-height: 34px; padding: 6px 8px; background: white; }
    button { border: 1px solid #0f56c4; border-radius: 6px; min-height: 32px; padding: 5px 10px; background: var(--brand); color: white; cursor: pointer; }
    button.secondary { background: white; color: var(--brand); }
    button.warn { border-color: var(--danger); background: var(--danger); }
    button.small { min-height: 28px; padding: 3px 8px; font-size: 12px; }
    pre { white-space: pre-wrap; word-break: break-word; margin: 0; }
    .two { display: grid; grid-template-columns: minmax(0, 1.5fr) minmax(320px, 1fr); gap: 18px; }
    .bars { display: grid; gap: 8px; }
    .bar { display:grid; grid-template-columns: 110px 1fr 42px; gap: 8px; align-items:center; font-size:13px; }
    .track { height: 10px; background:#e5e7eb; border-radius:999px; overflow:hidden; }
    .fill { height: 100%; background: var(--brand); }
    @media (max-width: 900px) { .grid, .two { grid-template-columns: 1fr; } header { align-items:flex-start; flex-direction:column; } }
  </style>
</head>
<body>
  <header>
    <h1>轻量端口蜜罐管理台</h1>
    <div class="row">
      <span id="tcpStatus" class="pill">加载中</span>
      <button class="secondary" onclick="apiPost('/api/service/start')">启动服务</button>
      <button class="warn" onclick="apiPost('/api/service/stop')">停止服务</button>
      <button class="secondary" onclick="apiPost('/api/alerts/test')">测试告警</button>
      <button class="secondary" onclick="apiPost('/api/alerts/stop')">停止声音</button>
    </div>
  </header>
  <main>
    <section>
      <div class="grid">
        <div class="metric"><b id="mNodes">0</b><span class="muted">节点总数</span></div>
        <div class="metric"><b id="mOnline">0</b><span class="muted">在线节点</span></div>
        <div class="metric"><b id="mEvents">0</b><span class="muted">攻击事件</span></div>
        <div class="metric"><b id="mTcp">-</b><span class="muted">TCP 接入端口</span></div>
      </div>
    </section>
    <div class="two">
      <section>
        <h2>节点状态与控制</h2>
        <table>
          <thead><tr><th>状态</th><th>节点</th><th>IP</th><th>系统</th><th>监听端口</th><th>最后心跳</th><th>控制</th></tr></thead>
          <tbody id="nodes"></tbody>
        </table>
      </section>
      <section>
        <h2>攻击源 IP TOP</h2>
        <div id="topIps" class="bars"></div>
      </section>
    </div>
    <section>
      <h2>日志筛选</h2>
      <div class="row">
        <input id="fNode" placeholder="节点 ID">
        <input id="fSource" placeholder="源 IP">
        <input id="fPort" placeholder="目标端口">
        <button onclick="loadEvents()">查询</button>
      </div>
    </section>
    <section>
      <h2>攻击日志</h2>
      <table><thead><tr><th>时间</th><th>节点</th><th>源地址</th><th>目标端口</th><th>模式</th><th>内容片段</th></tr></thead><tbody id="events"></tbody></table>
    </section>
    <section>
      <h2>客户端生成</h2>
      <div class="row">
        <input id="bHost" placeholder="服务端 IP" value="127.0.0.1">
        <input id="bPort" placeholder="服务端端口" value="9443">
        <input id="bPorts" placeholder="监听端口，逗号分隔" value="21,22,23,80,445,3389">
        <select id="bStealth"><option value="true">默认隐身模式</option><option value="false">普通模式</option></select>
        <select id="bPlatform"><option value="windows-x64">Windows x64</option><option value="linux-x64">Linux x64</option><option value="linux-arm64">Linux arm64</option><option value="macos-x64">macOS x64</option></select>
        <button onclick="buildClient()">生成配置包</button>
      </div>
      <pre id="buildResult" class="muted"></pre>
    </section>
    <section>
      <h2>客户端自动更新</h2>
      <div class="row">
        <select id="uPlatform"><option value="windows-x64">Windows x64</option><option value="linux-x64">Linux x64</option><option value="linux-arm64">Linux arm64</option><option value="macos-x64">macOS x64</option></select>
        <input id="uVersion" placeholder="版本号" value="0.1.0">
        <input id="uNotes" placeholder="更新说明" value="manual publish">
        <button onclick="publishUpdate()">发布当前二进制</button>
        <button class="secondary" onclick="loadUpdateManifest()">查看更新</button>
      </div>
      <pre id="updateResult" class="muted"></pre>
    </section>
    <section>
      <h2>服务端日志</h2>
      <table><thead><tr><th>时间</th><th>级别</th><th>内容</th></tr></thead><tbody id="serverLogs"></tbody></table>
    </section>
  </main>
  <script>
    const fmt = ts => ts ? new Date(ts * 1000).toLocaleString() : '-';
    async function getJson(url) { const r = await fetch(url); return await r.json(); }
    async function apiPost(url, body) {
      await fetch(url, {method:'POST', headers:{'Content-Type':'application/json'}, body: body ? JSON.stringify(body) : '{}'});
      await refresh();
    }
    function esc(v) { return String(v ?? '').replace(/[&<>"']/g, s => ({'&':'&amp;','<':'&lt;','>':'&gt;','"':'&quot;',"'":'&#39;'}[s])); }
    function bars(el, rows, label) {
      const max = Math.max(1, ...rows.map(r => r.count));
      el.innerHTML = rows.map(r => `<div class="bar"><span>${esc(r[label])}</span><span class="track"><span class="fill" style="display:block;width:${Math.round(r.count/max*100)}%"></span></span><b>${r.count}</b></div>`).join('') || '<span class="muted">暂无数据</span>';
    }
    function commandButtons(n) {
      const id = esc(n.node_id);
      return `<div class="row">
        <button class="small secondary" onclick="queueCommand('${id}','start_all')">启动</button>
        <button class="small warn" onclick="queueCommand('${id}','stop_all')">停止</button>
        <button class="small secondary" onclick="setPorts('${id}', '${esc((n.listen_ports||[]).join(','))}')">改端口</button>
        ${n.pending_commands ? `<span class="muted">待下发 ${n.pending_commands}</span>` : ''}
      </div>`;
    }
    async function refresh() {
      const data = await getJson('/api/status');
      mNodes.textContent = data.stats.nodes; mOnline.textContent = data.stats.online_nodes; mEvents.textContent = data.stats.events; mTcp.textContent = data.service.port;
      tcpStatus.textContent = data.service.running ? 'TCP 服务运行中' : 'TCP 服务已停止';
      tcpStatus.className = 'pill ' + (data.service.running ? 'online' : 'offline');
      nodes.innerHTML = data.nodes.map(n => `<tr><td><span class="pill ${n.online ? 'online':'offline'}">${n.online ? '在线':'离线'}</span></td><td>${esc(n.node_id)}<div class="muted">${esc(n.hostname)}</div></td><td>${esc(n.ip)}</td><td>${esc(n.os)} ${esc(n.arch)}</td><td>${esc((n.listen_ports||[]).join(','))}</td><td>${fmt(n.last_heartbeat)}</td><td>${commandButtons(n)}</td></tr>`).join('');
      bars(topIps, data.stats.top_ips, 'source_ip');
      serverLogs.innerHTML = data.server_logs.map(l => `<tr><td>${fmt(l.ts)}</td><td>${esc(l.level)}</td><td>${esc(l.message)}</td></tr>`).join('');
      await loadEvents();
    }
    async function loadEvents() {
      const q = new URLSearchParams({node_id:fNode.value, source_ip:fSource.value, target_port:fPort.value});
      const rows = await getJson('/api/events?' + q.toString());
      events.innerHTML = rows.map(e => `<tr><td>${fmt(e.ts)}</td><td>${esc(e.node_id)}</td><td>${esc(e.source_ip)}:${esc(e.source_port||'-')}</td><td>${esc(e.target_port)}</td><td>${esc(e.mode)}</td><td><pre>${esc(e.content)}</pre></td></tr>`).join('');
    }
    async function queueCommand(nodeId, command, payload) {
      await apiPost('/api/nodes/command', {node_id: nodeId, command, payload: payload || {}});
    }
    async function setPorts(nodeId, current) {
      const text = prompt('输入新的监听端口，多个端口用英文逗号分隔', current);
      if (text === null) return;
      const ports = text.split(',').map(v => Number(v.trim())).filter(v => Number.isInteger(v) && v > 0 && v < 65536);
      await queueCommand(nodeId, 'set_ports', {listen_ports: ports});
    }
    async function buildClient() {
      const body = {server_host:bHost.value, server_port:Number(bPort.value), listen_ports:bPorts.value.split(',').map(v=>Number(v.trim())).filter(Boolean), stealth_mode:bStealth.value==='true', platforms:[bPlatform.value]};
      const r = await fetch('/api/client-package', {method:'POST', headers:{'Content-Type':'application/json'}, body: JSON.stringify(body)});
      buildResult.textContent = JSON.stringify(await r.json(), null, 2);
    }
    async function publishUpdate() {
      const body = {platform:uPlatform.value, version:uVersion.value, notes:uNotes.value};
      const r = await fetch('/api/client-updates/publish', {method:'POST', headers:{'Content-Type':'application/json'}, body: JSON.stringify(body)});
      updateResult.textContent = JSON.stringify(await r.json(), null, 2);
    }
    async function loadUpdateManifest() {
      const r = await fetch(`/api/client-updates/${uPlatform.value}/manifest`);
      updateResult.textContent = JSON.stringify(await r.json(), null, 2);
    }
    refresh(); setInterval(refresh, 5000);
  </script>
</body>
</html>"""


class WebHandler(BaseHTTPRequestHandler):
    server_version = "PortHoneypotWeb/0.1"

    def do_GET(self) -> None:
        parsed = urllib.parse.urlparse(self.path)
        if parsed.path == "/":
            self._send(HTTPStatus.OK, HTML, "text/html; charset=utf-8")
            return
        if parsed.path == "/api/status":
            self._json(self._app_status())
            return
        if parsed.path == "/api/events":
            query = urllib.parse.parse_qs(parsed.query)
            filters = {key: values[0] for key, values in query.items() if values and values[0]}
            self._json(self.server.database.query_events(filters))  # type: ignore[attr-defined]
            return
        if parsed.path == "/api/targets":
            self._json({"targets": TARGETS})
            return
        if parsed.path.startswith("/api/client-updates/") and parsed.path.endswith("/manifest"):
            platform = parsed.path.split("/")[-2]
            self._json(self.server.update_manager.manifest(platform))  # type: ignore[attr-defined]
            return
        if parsed.path.startswith("/api/client-updates/") and parsed.path.endswith("/download"):
            platform = parsed.path.split("/")[-2]
            binary = self.server.update_manager.binary_path(platform)  # type: ignore[attr-defined]
            if binary is None:
                self._json({"error": "update binary not found"}, HTTPStatus.NOT_FOUND)
                return
            self._send_file(binary)
            return
        self._json({"error": "not found"}, HTTPStatus.NOT_FOUND)

    def do_POST(self) -> None:
        parsed = urllib.parse.urlparse(self.path)
        body = self._read_json()
        if parsed.path == "/api/service/start":
            self.server.tcp_service.start()  # type: ignore[attr-defined]
            self._json({"ok": True})
            return
        if parsed.path == "/api/service/stop":
            self.server.tcp_service.stop()  # type: ignore[attr-defined]
            self._json({"ok": True})
            return
        if parsed.path == "/api/alerts/test":
            self._json(self.server.alerts.test())  # type: ignore[attr-defined]
            return
        if parsed.path == "/api/alerts/stop":
            self._json(self.server.alerts.stop_sound())  # type: ignore[attr-defined]
            return
        if parsed.path == "/api/nodes/command":
            result = self._enqueue_node_command(body)
            self._json(result)
            return
        if parsed.path == "/api/client-package":
            result = self.server.client_builder.build_package(  # type: ignore[attr-defined]
                server_host=str(body.get("server_host", "127.0.0.1")),
                server_port=int(body.get("server_port", 9443)),
                listen_ports=[int(p) for p in body.get("listen_ports", [])],
                stealth_mode=bool(body.get("stealth_mode", True)),
                platforms=[str(p) for p in body.get("platforms", ["windows-x64"])],
            )
            self._json(result)
            return
        if parsed.path == "/api/client-updates/publish":
            try:
                result = self.server.update_manager.publish(  # type: ignore[attr-defined]
                    platform=str(body.get("platform", "windows-x64")),
                    version=str(body.get("version", "0.1.0")),
                    source=str(body["source"]) if body.get("source") else None,
                    notes=str(body.get("notes", "")),
                )
            except Exception as exc:
                self._json({"ok": False, "error": str(exc)}, HTTPStatus.BAD_REQUEST)
                return
            result["ok"] = True
            self._json(result)
            return
        self._json({"error": "not found"}, HTTPStatus.NOT_FOUND)

    def log_message(self, fmt: str, *args: Any) -> None:
        self.server.database.log("WEB", fmt % args)  # type: ignore[attr-defined]

    def _app_status(self) -> dict[str, Any]:
        return {
            "service": self.server.tcp_service.status(),  # type: ignore[attr-defined]
            "stats": self.server.database.stats(),  # type: ignore[attr-defined]
            "nodes": self.server.database.list_nodes(),  # type: ignore[attr-defined]
            "server_logs": self.server.database.recent_server_logs(50),  # type: ignore[attr-defined]
        }

    def _enqueue_node_command(self, body: dict[str, Any]) -> dict[str, Any]:
        node_id = str(body.get("node_id", "")).strip()
        command = str(body.get("command", "")).strip()
        payload = body.get("payload") if isinstance(body.get("payload"), dict) else {}
        if not node_id:
            return {"ok": False, "error": "node_id is required"}
        if command not in {"start_all", "stop_all", "set_ports"}:
            return {"ok": False, "error": "unsupported command"}
        if command == "set_ports":
            ports = payload.get("listen_ports", [])
            if not isinstance(ports, list) or not all(isinstance(p, int) and 0 < p < 65536 for p in ports):
                return {"ok": False, "error": "payload.listen_ports must be a list of valid ports"}
        command_id = self.server.database.enqueue_command(node_id, command, payload)  # type: ignore[attr-defined]
        return {"ok": True, "command_id": command_id}

    def _read_json(self) -> dict[str, Any]:
        size = int(self.headers.get("Content-Length", "0") or "0")
        if size <= 0:
            return {}
        raw = self.rfile.read(size)
        return json.loads(raw.decode("utf-8"))

    def _json(self, value: Any, status: HTTPStatus = HTTPStatus.OK) -> None:
        self._send(status, json.dumps(value, ensure_ascii=False).encode("utf-8"), "application/json; charset=utf-8")

    def _send(self, status: HTTPStatus, payload: str | bytes, content_type: str) -> None:
        if isinstance(payload, str):
            payload = payload.encode("utf-8")
        self.send_response(status)
        self.send_header("Content-Type", content_type)
        self.send_header("Content-Length", str(len(payload)))
        self.send_header("Cache-Control", "no-store")
        self.end_headers()
        self.wfile.write(payload)

    def _send_file(self, path: Any) -> None:
        data = path.read_bytes()
        self.send_response(HTTPStatus.OK)
        self.send_header("Content-Type", "application/octet-stream")
        self.send_header("Content-Length", str(len(data)))
        self.send_header("Cache-Control", "no-store")
        self.end_headers()
        self.wfile.write(data)


class HoneypotWebServer(ThreadingHTTPServer):
    daemon_threads = True

    def __init__(
        self,
        address: tuple[str, int],
        database: Database,
        alerts: AlertManager,
        tcp_service: TcpService,
        client_builder: ClientBuilder,
        update_manager: UpdateManager,
    ):
        super().__init__(address, WebHandler)
        self.database = database
        self.alerts = alerts
        self.tcp_service = tcp_service
        self.client_builder = client_builder
        self.update_manager = update_manager


class WebService:
    def __init__(
        self,
        host: str,
        port: int,
        database: Database,
        alerts: AlertManager,
        tcp_service: TcpService,
        client_builder: ClientBuilder,
        update_manager: UpdateManager,
    ):
        self.host = host
        self.port = port
        self.database = database
        self.alerts = alerts
        self.tcp_service = tcp_service
        self.client_builder = client_builder
        self.update_manager = update_manager
        self._server: HoneypotWebServer | None = None
        self._thread: threading.Thread | None = None

    def start(self) -> None:
        if self._server is not None:
            return
        self._server = HoneypotWebServer(
            (self.host, self.port),
            self.database,
            self.alerts,
            self.tcp_service,
            self.client_builder,
            self.update_manager,
        )
        self._thread = threading.Thread(target=self._server.serve_forever, daemon=True)
        self._thread.start()
        self.database.log("INFO", f"Web service started at http://{self.host}:{self.port}")

    def stop(self) -> None:
        if self._server is None:
            return
        self._server.shutdown()
        self._server.server_close()
        self._server = None
        self._thread = None

    def serve_forever(self) -> None:
        self.start()
        try:
            while True:
                time.sleep(3600)
        except KeyboardInterrupt:
            self.stop()
