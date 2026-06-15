from __future__ import annotations

import base64
import hashlib
import hmac
import json
import platform
import smtplib
import ssl
import threading
import time
import urllib.parse
import urllib.request
from email.message import EmailMessage
from typing import Any

from .config import AlertConfig, WebhookConfig
from .database import Database


class AlertManager:
    def __init__(self, config: AlertConfig, database: Database):
        self.config = config
        self.database = database
        self._sound_stop = threading.Event()

    def attack(self, event: dict[str, Any]) -> None:
        message = (
            f"节点 {event.get('node_id')} 端口 {event.get('target_port')} "
            f"被 {event.get('source_ip')}:{event.get('source_port') or '-'} 访问"
        )
        self.emit("attack", f"{event.get('node_id')}:{event.get('source_ip')}:{event.get('target_port')}", message)
        self._abnormal_probe(event)

    def node_disconnect(self, node: dict[str, Any]) -> None:
        message = f"节点 {node.get('node_id')} 已断连，最后心跳 {node.get('last_heartbeat')}"
        self.emit("node_disconnect", str(node.get("node_id")), message)

    def test(self) -> dict[str, Any]:
        self.emit("attack", "manual-test", "这是一条端口蜜罐测试告警")
        return {"ok": True, "message": "test alert emitted"}

    def stop_sound(self) -> dict[str, Any]:
        self._sound_stop.set()
        return {"ok": True, "message": "sound stop requested"}

    def emit(self, event_type: str, dedupe_key: str, message: str) -> None:
        if not self.config.enabled or event_type not in self.config.event_types:
            return
        now = int(time.time())
        last = self.database.last_alert_ts(event_type, dedupe_key)
        if last and now - last < self.config.rate_limit_seconds:
            return
        self.database.record_alert(event_type, dedupe_key, message)
        self.database.log("ALERT", message)

        if self.config.local_sound:
            threading.Thread(target=self._local_sound, daemon=True).start()
        self._send_email(event_type, message)
        self._send_dingtalk(event_type, message)
        self._send_plain_webhook("feishu", self.config.feishu, message)
        self._send_plain_webhook("wecom", self.config.wecom, message)

    def _abnormal_probe(self, event: dict[str, Any]) -> None:
        source_ip = str(event.get("source_ip", "")).strip()
        if not source_ip or "abnormal_probe" not in self.config.event_types:
            return
        activity = self.database.probe_activity(source_ip, self.config.abnormal_probe_window_seconds)
        if activity["event_count"] < self.config.abnormal_probe_min_events:
            return
        if activity["distinct_ports"] < self.config.abnormal_probe_distinct_ports:
            return
        ports = ", ".join(str(row["target_port"]) for row in activity["ports"][:8])
        message = (
            f"异常端口探测：源 IP {source_ip} 在 {activity['window_seconds']} 秒内 "
            f"触发 {activity['event_count']} 次访问，涉及 {activity['distinct_ports']} 个端口"
        )
        if ports:
            message += f"，主要端口：{ports}"
        self.emit("abnormal_probe", source_ip, message)

    def _local_sound(self) -> None:
        if platform.system().lower() != "windows":
            return
        try:
            import winsound

            self._sound_stop.clear()
            for _ in range(3):
                if self._sound_stop.is_set():
                    break
                winsound.Beep(1800, 180)
                winsound.Beep(1200, 180)
        except Exception as exc:
            self.database.log("WARN", f"local sound alert failed: {exc}")

    def _send_email(self, event_type: str, message: str) -> None:
        cfg = self.config.email
        if not cfg.enabled or not cfg.receivers:
            return
        try:
            mail = EmailMessage()
            mail["Subject"] = f"[端口蜜罐告警] {event_type}"
            mail["From"] = cfg.sender or cfg.username
            mail["To"] = ", ".join(cfg.receivers)
            mail.set_content(message)
            if cfg.use_ssl:
                context = ssl.create_default_context()
                with smtplib.SMTP_SSL(cfg.smtp_host, cfg.smtp_port, context=context, timeout=10) as smtp:
                    if cfg.username:
                        smtp.login(cfg.username, cfg.password)
                    smtp.send_message(mail)
            else:
                with smtplib.SMTP(cfg.smtp_host, cfg.smtp_port, timeout=10) as smtp:
                    smtp.starttls()
                    if cfg.username:
                        smtp.login(cfg.username, cfg.password)
                    smtp.send_message(mail)
        except Exception as exc:
            self.database.log("WARN", f"email alert failed: {exc}")

    def _send_dingtalk(self, event_type: str, message: str) -> None:
        cfg = self.config.dingtalk
        if not cfg.enabled or not cfg.url:
            return
        url = cfg.url
        if cfg.secret:
            timestamp = str(round(time.time() * 1000))
            sign_source = f"{timestamp}\n{cfg.secret}".encode("utf-8")
            sign = base64.b64encode(hmac.new(cfg.secret.encode("utf-8"), sign_source, hashlib.sha256).digest())
            url += ("&" if "?" in url else "?") + urllib.parse.urlencode(
                {"timestamp": timestamp, "sign": sign.decode("ascii")}
            )
        payload = {"msgtype": "text", "text": {"content": f"[{event_type}] {message}"}}
        self._post_json("dingtalk", url, payload)

    def _send_plain_webhook(self, channel: str, cfg: WebhookConfig, message: str) -> None:
        if not cfg.enabled or not cfg.url:
            return
        payload = {"msg_type": "text", "content": {"text": message}}
        if channel == "wecom":
            payload = {"msgtype": "text", "text": {"content": message}}
        self._post_json(channel, cfg.url, payload)

    def _post_json(self, channel: str, url: str, payload: dict[str, Any]) -> None:
        try:
            data = json.dumps(payload, ensure_ascii=False).encode("utf-8")
            req = urllib.request.Request(
                url,
                data=data,
                headers={"Content-Type": "application/json"},
                method="POST",
            )
            with urllib.request.urlopen(req, timeout=10) as resp:
                resp.read()
        except Exception as exc:
            self.database.log("WARN", f"{channel} webhook alert failed: {exc}")
