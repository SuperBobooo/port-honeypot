from __future__ import annotations

import datetime as dt
import json
import threading
import tkinter as tk
import webbrowser
from pathlib import Path
from tkinter import messagebox, simpledialog, ttk
from typing import Any

from .app import HoneypotApp
from .config import DEFAULT_CONFIG_PATH


class DesktopManager:
    def __init__(self, root: tk.Tk, config_path: Path = DEFAULT_CONFIG_PATH):
        self.root = root
        self.root.title("轻量端口蜜罐管理端")
        self.root.geometry("1180x760")
        self.root.minsize(980, 640)
        self.root.protocol("WM_DELETE_WINDOW", self.confirm_exit)

        self.app = HoneypotApp(config_path)
        self._refreshing = False
        self._closed = False

        self._build_layout()
        self._start_app()
        self.refresh_all()

    def _start_app(self) -> None:
        try:
            self.app.start()
            self.set_status(f"服务已启动：TCP {self.app.config.tcp.host}:{self.app.config.tcp.port}，Web {self.web_url}")
        except Exception as exc:
            messagebox.showerror("启动失败", f"服务启动失败：{exc}")
            self.set_status(f"服务启动失败：{exc}")

    @property
    def web_url(self) -> str:
        return f"http://{self.app.config.web.host}:{self.app.config.web.port}"

    def _build_layout(self) -> None:
        self._build_menu()
        self.status_var = tk.StringVar(value="准备就绪")
        self.metrics = {
            "nodes": tk.StringVar(value="0"),
            "online": tk.StringVar(value="0"),
            "events": tk.StringVar(value="0"),
            "tcp": tk.StringVar(value="-"),
        }

        header = ttk.Frame(self.root, padding=(12, 10))
        header.pack(fill=tk.X)
        ttk.Label(header, text="轻量端口蜜罐管理端", font=("Microsoft YaHei UI", 16, "bold")).pack(side=tk.LEFT)
        ttk.Button(header, text="打开 Web 管理台", command=self.open_dashboard).pack(side=tk.RIGHT, padx=(8, 0))
        ttk.Button(header, text="刷新", command=self.refresh_all).pack(side=tk.RIGHT)

        self.notebook = ttk.Notebook(self.root)
        self.notebook.pack(fill=tk.BOTH, expand=True, padx=12, pady=(0, 8))

        self.dashboard_tab = ttk.Frame(self.notebook, padding=10)
        self.nodes_tab = ttk.Frame(self.notebook, padding=10)
        self.events_tab = ttk.Frame(self.notebook, padding=10)
        self.ops_tab = ttk.Frame(self.notebook, padding=10)
        self.logs_tab = ttk.Frame(self.notebook, padding=10)

        self.notebook.add(self.dashboard_tab, text="总览")
        self.notebook.add(self.nodes_tab, text="节点管理")
        self.notebook.add(self.events_tab, text="攻击日志")
        self.notebook.add(self.ops_tab, text="服务/打包/更新")
        self.notebook.add(self.logs_tab, text="服务端日志")

        self._build_dashboard()
        self._build_nodes()
        self._build_events()
        self._build_ops()
        self._build_logs()

        status = ttk.Label(self.root, textvariable=self.status_var, anchor=tk.W, padding=(12, 4))
        status.pack(fill=tk.X)

    def _build_menu(self) -> None:
        menu = tk.Menu(self.root)
        file_menu = tk.Menu(menu, tearoff=False)
        file_menu.add_command(label="打开 Web 管理台", command=self.open_dashboard)
        file_menu.add_separator()
        file_menu.add_command(label="退出", command=self.confirm_exit)
        menu.add_cascade(label="文件", menu=file_menu)

        service_menu = tk.Menu(menu, tearoff=False)
        service_menu.add_command(label="启动 TCP 服务", command=self.start_tcp)
        service_menu.add_command(label="停止 TCP 服务", command=self.stop_tcp)
        service_menu.add_separator()
        service_menu.add_command(label="测试告警", command=self.test_alert)
        service_menu.add_command(label="停止声音", command=self.stop_sound)
        menu.add_cascade(label="服务", menu=service_menu)
        self.root.config(menu=menu)

    def _build_dashboard(self) -> None:
        metric_frame = ttk.Frame(self.dashboard_tab)
        metric_frame.pack(fill=tk.X, pady=(0, 12))
        items = [
            ("节点总数", self.metrics["nodes"]),
            ("在线节点", self.metrics["online"]),
            ("攻击事件", self.metrics["events"]),
            ("TCP 端口", self.metrics["tcp"]),
        ]
        for label, var in items:
            card = ttk.LabelFrame(metric_frame, text=label, padding=12)
            card.pack(side=tk.LEFT, fill=tk.X, expand=True, padx=(0, 10))
            ttk.Label(card, textvariable=var, font=("Segoe UI", 22, "bold")).pack(anchor=tk.W)

        charts = ttk.Frame(self.dashboard_tab)
        charts.pack(fill=tk.BOTH, expand=True)
        left = ttk.LabelFrame(charts, text="攻击源 IP TOP", padding=8)
        left.pack(side=tk.LEFT, fill=tk.BOTH, expand=True, padx=(0, 8))
        right = ttk.LabelFrame(charts, text="目标端口 TOP", padding=8)
        right.pack(side=tk.LEFT, fill=tk.BOTH, expand=True)
        self.top_ip_canvas = tk.Canvas(left, height=320, background="#ffffff", highlightthickness=0)
        self.top_ip_canvas.pack(fill=tk.BOTH, expand=True)
        self.top_port_canvas = tk.Canvas(right, height=320, background="#ffffff", highlightthickness=0)
        self.top_port_canvas.pack(fill=tk.BOTH, expand=True)

    def _build_nodes(self) -> None:
        toolbar = ttk.Frame(self.nodes_tab)
        toolbar.pack(fill=tk.X, pady=(0, 8))
        ttk.Button(toolbar, text="刷新节点", command=self.refresh_nodes).pack(side=tk.LEFT)
        ttk.Button(toolbar, text="启动监听", command=lambda: self.queue_selected_command("start_all")).pack(side=tk.LEFT, padx=6)
        ttk.Button(toolbar, text="停止监听", command=lambda: self.queue_selected_command("stop_all")).pack(side=tk.LEFT)
        ttk.Button(toolbar, text="修改端口", command=self.set_selected_ports).pack(side=tk.LEFT, padx=6)

        columns = ("online", "node_id", "hostname", "ip", "os", "ports", "heartbeat", "pending")
        self.nodes_tree = ttk.Treeview(self.nodes_tab, columns=columns, show="headings", height=18)
        headings = {
            "online": "状态",
            "node_id": "节点 ID",
            "hostname": "主机名",
            "ip": "IP",
            "os": "系统",
            "ports": "监听端口",
            "heartbeat": "最后心跳",
            "pending": "待下发",
        }
        widths = {"online": 70, "node_id": 210, "hostname": 120, "ip": 120, "os": 110, "ports": 180, "heartbeat": 150, "pending": 70}
        for col in columns:
            self.nodes_tree.heading(col, text=headings[col])
            self.nodes_tree.column(col, width=widths[col], anchor=tk.W)
        self.nodes_tree.pack(fill=tk.BOTH, expand=True)

    def _build_events(self) -> None:
        filters = ttk.LabelFrame(self.events_tab, text="筛选", padding=8)
        filters.pack(fill=tk.X, pady=(0, 8))
        self.filter_node = tk.StringVar()
        self.filter_source = tk.StringVar()
        self.filter_port = tk.StringVar()
        for text, var in [("节点 ID", self.filter_node), ("源 IP", self.filter_source), ("目标端口", self.filter_port)]:
            ttk.Label(filters, text=text).pack(side=tk.LEFT, padx=(0, 4))
            ttk.Entry(filters, textvariable=var, width=18).pack(side=tk.LEFT, padx=(0, 12))
        ttk.Button(filters, text="查询", command=self.refresh_events).pack(side=tk.LEFT)

        columns = ("ts", "node_id", "source", "target_port", "mode", "content")
        self.events_tree = ttk.Treeview(self.events_tab, columns=columns, show="headings", height=20)
        headings = {"ts": "时间", "node_id": "节点", "source": "源地址", "target_port": "目标端口", "mode": "模式", "content": "内容片段"}
        widths = {"ts": 150, "node_id": 210, "source": 160, "target_port": 80, "mode": 90, "content": 360}
        for col in columns:
            self.events_tree.heading(col, text=headings[col])
            self.events_tree.column(col, width=widths[col], anchor=tk.W)
        self.events_tree.pack(fill=tk.BOTH, expand=True)

    def _build_ops(self) -> None:
        service = ttk.LabelFrame(self.ops_tab, text="服务控制", padding=10)
        service.pack(fill=tk.X, pady=(0, 10))
        ttk.Button(service, text="启动 TCP 服务", command=self.start_tcp).pack(side=tk.LEFT)
        ttk.Button(service, text="停止 TCP 服务", command=self.stop_tcp).pack(side=tk.LEFT, padx=8)
        ttk.Button(service, text="测试告警", command=self.test_alert).pack(side=tk.LEFT)
        ttk.Button(service, text="停止声音", command=self.stop_sound).pack(side=tk.LEFT, padx=8)
        ttk.Button(service, text="打开 Web 管理台", command=self.open_dashboard).pack(side=tk.LEFT)

        builder = ttk.LabelFrame(self.ops_tab, text="客户端生成", padding=10)
        builder.pack(fill=tk.X, pady=(0, 10))
        self.build_host = tk.StringVar(value="127.0.0.1")
        self.build_ports = tk.StringVar(value="21,22,23,80,445,3389")
        self.build_platform = tk.StringVar(value="windows-x64")
        self.build_stealth = tk.BooleanVar(value=True)
        ttk.Label(builder, text="服务端 IP").pack(side=tk.LEFT)
        ttk.Entry(builder, textvariable=self.build_host, width=16).pack(side=tk.LEFT, padx=(4, 10))
        ttk.Label(builder, text="监听端口").pack(side=tk.LEFT)
        ttk.Entry(builder, textvariable=self.build_ports, width=28).pack(side=tk.LEFT, padx=(4, 10))
        ttk.Combobox(builder, textvariable=self.build_platform, values=("windows-x64", "linux-x64", "linux-arm64", "macos-x64"), width=14, state="readonly").pack(side=tk.LEFT)
        ttk.Checkbutton(builder, text="隐身模式", variable=self.build_stealth).pack(side=tk.LEFT, padx=8)
        ttk.Button(builder, text="生成配置包", command=self.build_client_package).pack(side=tk.LEFT)

        updater = ttk.LabelFrame(self.ops_tab, text="客户端更新发布", padding=10)
        updater.pack(fill=tk.X, pady=(0, 10))
        self.update_platform = tk.StringVar(value="windows-x64")
        self.update_version = tk.StringVar(value="0.1.1")
        self.update_notes = tk.StringVar(value="desktop publish")
        ttk.Combobox(updater, textvariable=self.update_platform, values=("windows-x64", "linux-x64", "linux-arm64", "macos-x64"), width=14, state="readonly").pack(side=tk.LEFT)
        ttk.Label(updater, text="版本").pack(side=tk.LEFT, padx=(10, 4))
        ttk.Entry(updater, textvariable=self.update_version, width=12).pack(side=tk.LEFT, padx=(0, 10))
        ttk.Label(updater, text="说明").pack(side=tk.LEFT, padx=(0, 4))
        ttk.Entry(updater, textvariable=self.update_notes, width=28).pack(side=tk.LEFT, padx=(0, 10))
        ttk.Button(updater, text="发布更新", command=self.publish_update).pack(side=tk.LEFT)

        result_frame = ttk.LabelFrame(self.ops_tab, text="操作结果", padding=8)
        result_frame.pack(fill=tk.BOTH, expand=True)
        self.ops_result = tk.Text(result_frame, height=12, wrap=tk.WORD)
        self.ops_result.pack(fill=tk.BOTH, expand=True)

    def _build_logs(self) -> None:
        toolbar = ttk.Frame(self.logs_tab)
        toolbar.pack(fill=tk.X, pady=(0, 8))
        ttk.Button(toolbar, text="刷新日志", command=self.refresh_logs).pack(side=tk.LEFT)
        columns = ("ts", "level", "message")
        self.logs_tree = ttk.Treeview(self.logs_tab, columns=columns, show="headings", height=22)
        for col, text, width in [("ts", "时间", 150), ("level", "级别", 80), ("message", "内容", 760)]:
            self.logs_tree.heading(col, text=text)
            self.logs_tree.column(col, width=width, anchor=tk.W)
        self.logs_tree.pack(fill=tk.BOTH, expand=True)

    def refresh_all(self) -> None:
        if self._closed or self._refreshing:
            return
        self._refreshing = True
        try:
            self.refresh_dashboard()
            self.refresh_nodes()
            self.refresh_events()
            self.refresh_logs()
        except Exception as exc:
            self.set_status(f"刷新失败：{exc}")
        finally:
            self._refreshing = False
            if not self._closed:
                self.root.after(5000, self.refresh_all)

    def refresh_dashboard(self) -> None:
        stats = self.app.database.stats()
        service = self.app.tcp_service.status()
        self.metrics["nodes"].set(str(stats["nodes"]))
        self.metrics["online"].set(str(stats["online_nodes"]))
        self.metrics["events"].set(str(stats["events"]))
        self.metrics["tcp"].set(str(service["port"]))
        self._draw_bars(self.top_ip_canvas, stats["top_ips"], "source_ip")
        self._draw_bars(self.top_port_canvas, stats["top_ports"], "target_port")

    def refresh_nodes(self) -> None:
        rows = self.app.database.list_nodes()
        self._clear_tree(self.nodes_tree)
        for row in rows:
            self.nodes_tree.insert(
                "",
                tk.END,
                iid=row["node_id"],
                values=(
                    "在线" if row["online"] else "离线",
                    row["node_id"],
                    row["hostname"],
                    row["ip"],
                    f"{row['os']} {row['arch']}",
                    ",".join(str(p) for p in row["listen_ports"]),
                    fmt_ts(row["last_heartbeat"]),
                    row.get("pending_commands", 0),
                ),
            )

    def refresh_events(self) -> None:
        filters: dict[str, Any] = {"limit": 300}
        if self.filter_node.get().strip():
            filters["node_id"] = self.filter_node.get().strip()
        if self.filter_source.get().strip():
            filters["source_ip"] = self.filter_source.get().strip()
        if self.filter_port.get().strip():
            filters["target_port"] = self.filter_port.get().strip()
        rows = self.app.database.query_events(filters)
        self._clear_tree(self.events_tree)
        for row in rows:
            self.events_tree.insert(
                "",
                tk.END,
                values=(
                    fmt_ts(row["ts"]),
                    row["node_id"],
                    f"{row['source_ip']}:{row.get('source_port') or '-'}",
                    row["target_port"],
                    row["mode"],
                    row.get("content", "")[:160],
                ),
            )

    def refresh_logs(self) -> None:
        self._clear_tree(self.logs_tree)
        for row in self.app.database.recent_server_logs(300):
            self.logs_tree.insert("", tk.END, values=(fmt_ts(row["ts"]), row["level"], row["message"]))

    def queue_selected_command(self, command: str) -> None:
        node_id = self._selected_node_id()
        if not node_id:
            return
        self.app.database.enqueue_command(node_id, command, {})
        self.set_status(f"已下发命令：{command} -> {node_id}")
        self.refresh_nodes()

    def set_selected_ports(self) -> None:
        node_id = self._selected_node_id()
        if not node_id:
            return
        current = self.nodes_tree.set(node_id, "ports")
        text = simpledialog.askstring("修改监听端口", "多个端口用英文逗号分隔：", initialvalue=current, parent=self.root)
        if text is None:
            return
        try:
            ports = parse_ports(text)
        except ValueError as exc:
            messagebox.showerror("端口错误", str(exc))
            return
        self.app.database.enqueue_command(node_id, "set_ports", {"listen_ports": ports})
        self.set_status(f"已下发端口修改：{ports} -> {node_id}")
        self.refresh_nodes()

    def start_tcp(self) -> None:
        self.app.tcp_service.start()
        self.set_status("TCP 服务已启动")
        self.refresh_dashboard()

    def stop_tcp(self) -> None:
        self.app.tcp_service.stop()
        self.set_status("TCP 服务已停止")
        self.refresh_dashboard()

    def test_alert(self) -> None:
        self._set_ops_result(self.app.alerts.test())
        self.set_status("测试告警已发送")

    def stop_sound(self) -> None:
        self._set_ops_result(self.app.alerts.stop_sound())
        self.set_status("已请求停止声音")

    def open_dashboard(self) -> None:
        webbrowser.open(self.web_url)

    def build_client_package(self) -> None:
        try:
            result = self.app.client_builder.build_package(
                server_host=self.build_host.get().strip() or "127.0.0.1",
                server_port=self.app.config.tcp.port,
                listen_ports=parse_ports(self.build_ports.get()),
                stealth_mode=bool(self.build_stealth.get()),
                platforms=[self.build_platform.get()],
            )
            self._set_ops_result(result)
            self.set_status("客户端配置包已生成")
        except Exception as exc:
            messagebox.showerror("生成失败", str(exc))

    def publish_update(self) -> None:
        try:
            result = self.app.update_manager.publish(
                platform=self.update_platform.get(),
                version=self.update_version.get().strip() or "0.1.0",
                notes=self.update_notes.get(),
            )
            self._set_ops_result(result)
            self.set_status("客户端更新已发布")
        except Exception as exc:
            messagebox.showerror("发布失败", str(exc))

    def confirm_exit(self) -> None:
        if not messagebox.askyesno("退出确认", "确定要退出管理端并停止本地服务吗？"):
            return
        self._closed = True
        try:
            self.app.stop()
        finally:
            self.root.destroy()

    def set_status(self, text: str) -> None:
        self.status_var.set(text)

    def _selected_node_id(self) -> str | None:
        selected = self.nodes_tree.selection()
        if not selected:
            messagebox.showinfo("请选择节点", "请先在节点列表中选择一个节点。")
            return None
        return str(selected[0])

    def _set_ops_result(self, value: Any) -> None:
        self.ops_result.delete("1.0", tk.END)
        self.ops_result.insert(tk.END, json.dumps(value, ensure_ascii=False, indent=2))

    @staticmethod
    def _clear_tree(tree: ttk.Treeview) -> None:
        for item in tree.get_children():
            tree.delete(item)

    @staticmethod
    def _draw_bars(canvas: tk.Canvas, rows: list[dict[str, Any]], label_key: str) -> None:
        canvas.delete("all")
        width = max(canvas.winfo_width(), 420)
        max_count = max([int(row["count"]) for row in rows], default=1)
        y = 18
        if not rows:
            canvas.create_text(16, 18, anchor=tk.W, text="暂无数据", fill="#667085")
            return
        for row in rows[:10]:
            label = str(row[label_key])
            count = int(row["count"])
            bar_width = int((width - 150) * count / max_count)
            canvas.create_text(12, y + 8, anchor=tk.W, text=label, fill="#18202f")
            canvas.create_rectangle(120, y, 120 + bar_width, y + 18, fill="#1664d9", outline="")
            canvas.create_text(128 + bar_width, y + 9, anchor=tk.W, text=str(count), fill="#18202f")
            y += 30


def parse_ports(value: str) -> list[int]:
    ports: list[int] = []
    for raw in value.split(","):
        raw = raw.strip()
        if not raw:
            continue
        port = int(raw)
        if port <= 0 or port >= 65536:
            raise ValueError(f"端口超出范围：{port}")
        ports.append(port)
    if not ports:
        raise ValueError("至少需要一个端口。")
    return sorted(set(ports))


def fmt_ts(value: int | None) -> str:
    if not value:
        return "-"
    return dt.datetime.fromtimestamp(int(value)).strftime("%Y-%m-%d %H:%M:%S")


def run_desktop(config_path: Path = DEFAULT_CONFIG_PATH) -> None:
    root = tk.Tk()
    DesktopManager(root, config_path)
    root.mainloop()


def main() -> None:
    run_desktop(DEFAULT_CONFIG_PATH)


if __name__ == "__main__":
    main()
