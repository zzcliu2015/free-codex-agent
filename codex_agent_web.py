r"""
Codex Agent Identity 本地 Web 面板

启动：
  python .\codex_agent_web.py

默认打开：
  http://127.0.0.1:8765

说明：
- 只监听本机地址，供本地浏览器使用。
- 前端上传/粘贴的 AT 不落盘；生成后的 auth.json 会写入 results/时间戳/。
- 复用 codex_agent.py 中的 BatchProcessor 和 Sub2APIClient。
"""

from __future__ import annotations

import argparse
import contextlib
import json
import os
import sys
import threading
import time
import traceback
import uuid
import webbrowser
from dataclasses import dataclass, field
from http import HTTPStatus
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from pathlib import Path
from typing import Any
from urllib.parse import unquote, urlparse

import codex_agent as agent


APP_ROOT = Path(__file__).resolve().parent
WEB_ASSETS = APP_ROOT / "web_assets"
QR_GROUP_IMAGE = WEB_ASSETS / "qr_group.png"
DEFAULT_HOST = "127.0.0.1"
DEFAULT_PORT = 8765
MAX_BODY_BYTES = 20 * 1024 * 1024


@dataclass
class WebJob:
    id: str
    status: str = "queued"
    stop_requested: bool = False
    created_at: float = field(default_factory=time.time)
    updated_at: float = field(default_factory=time.time)
    finished_at: float | None = None
    logs: list[str] = field(default_factory=list)
    summary: dict[str, Any] | None = None
    run_dir: str = ""
    auth_dir: str = ""
    summary_path: str = ""
    csv_path: str = ""
    payload_path: str = ""
    errors_path: str = ""
    sub_import_result_path: str = ""
    sub_account_tests_path: str = ""
    error: str = ""

    def log(self, message: str, level: str = "INFO") -> None:
        self.updated_at = time.time()
        line = f"{time.strftime('%H:%M:%S')} [{level}] {agent.redact_text(str(message))}"
        self.logs.append(line)
        if len(self.logs) > 1200:
            self.logs = self.logs[-1200:]
        print(line)

    def to_dict(self) -> dict[str, Any]:
        return {
            "id": self.id,
            "status": self.status,
            "stop_requested": self.stop_requested,
            "created_at": self.created_at,
            "updated_at": self.updated_at,
            "finished_at": self.finished_at,
            "logs": self.logs,
            "summary": self.summary,
            "run_dir": self.run_dir,
            "auth_dir": self.auth_dir,
            "summary_path": self.summary_path,
            "csv_path": self.csv_path,
            "payload_path": self.payload_path,
            "errors_path": self.errors_path,
            "sub_import_result_path": self.sub_import_result_path,
            "sub_account_tests_path": self.sub_account_tests_path,
            "error": self.error,
        }

    def request_stop(self) -> None:
        self.stop_requested = True
        self.updated_at = time.time()
        if self.status in {"queued", "running"}:
            self.status = "stopping"
        self.log("已收到停止请求：当前正在执行的单条请求会先返回/超时，然后停止处理后续输入。", "WARN")


JOBS: dict[str, WebJob] = {}
JOBS_LOCK = threading.Lock()
RUN_LOCK = threading.Lock()


def read_json_body(handler: BaseHTTPRequestHandler) -> dict[str, Any]:
    length = int(handler.headers.get("Content-Length", "0") or "0")
    if length > MAX_BODY_BYTES:
        raise ValueError("请求体过大")
    raw = handler.rfile.read(length) if length else b"{}"
    if not raw.strip():
        return {}
    return json.loads(raw.decode("utf-8"))


def send_json(handler: BaseHTTPRequestHandler, data: Any, status: int = 200) -> None:
    payload = json.dumps(data, ensure_ascii=False).encode("utf-8")
    handler.send_response(status)
    handler.send_header("Content-Type", "application/json; charset=utf-8")
    handler.send_header("Content-Length", str(len(payload)))
    handler.send_header("Cache-Control", "no-store")
    handler.end_headers()
    handler.wfile.write(payload)


def send_text(handler: BaseHTTPRequestHandler, text: str, content_type: str = "text/plain; charset=utf-8") -> None:
    payload = text.encode("utf-8")
    handler.send_response(200)
    handler.send_header("Content-Type", content_type)
    handler.send_header("Content-Length", str(len(payload)))
    handler.end_headers()
    handler.wfile.write(payload)


def send_file(handler: BaseHTTPRequestHandler, path: Path, content_type: str) -> None:
    data = path.read_bytes()
    handler.send_response(200)
    handler.send_header("Content-Type", content_type)
    handler.send_header("Content-Length", str(len(data)))
    handler.send_header("Content-Disposition", f'attachment; filename="{path.name}"')
    handler.end_headers()
    handler.wfile.write(data)


def parse_items_from_web_content(content: str) -> list[agent.BatchInputItem]:
    content = (content or "").strip()
    items: list[agent.BatchInputItem] = []
    if not content:
        return items

    # 支持粘贴 sessions.json / auth.json / sub_import_payload.json
    if content.startswith("{") or content.startswith("["):
        try:
            data = json.loads(content)
            items.extend(agent.BatchInputLoader._items_from_json(data, source="web:textarea", label_hint="web"))
        except json.JSONDecodeError:
            pass

    # 支持一行一个 AT，也支持一行一个 JSON 字符串/对象。
    if not items:
        for line_no, raw_line in enumerate(content.splitlines(), 1):
            line = raw_line.strip()
            if not line or line.startswith("#"):
                continue
            parsed_items: list[agent.BatchInputItem] = []
            if line.startswith("{") or line.startswith("["):
                try:
                    parsed_items = agent.BatchInputLoader._items_from_json(
                        json.loads(line),
                        source=f"web:textarea:{line_no}",
                        label_hint=f"line_{line_no}",
                    )
                except json.JSONDecodeError:
                    parsed_items = []
            if parsed_items:
                items.extend(parsed_items)
                continue

            token = agent.extract_access_token_from_session(line)
            if token:
                items.append(
                    agent.BatchInputItem(
                        index=0,
                        source=f"web:textarea:{line_no}",
                        kind="access_token",
                        access_token=token,
                        label=f"line_{line_no}",
                    )
                )

    for i, item in enumerate(items, 1):
        item.index = i
        if item.access_token:
            item.token_fingerprint = agent.fingerprint(item.access_token)
    return items


def load_items_from_payload(payload: dict[str, Any]) -> list[agent.BatchInputItem]:
    input_path = str(payload.get("input_path") or "").strip()
    tokens_text = str(payload.get("tokens_text") or "").strip()

    items: list[agent.BatchInputItem] = []
    if input_path:
        items.extend(agent.BatchInputLoader.load(input_path))
    if tokens_text:
        pasted = parse_items_from_web_content(tokens_text)
        if items:
            offset = len(items)
            for idx, item in enumerate(pasted, offset + 1):
                item.index = idx
        items.extend(pasted)
    if not items:
        raise RuntimeError("请粘贴 AT/session JSON，或填写服务器可读取的输入路径")
    return items


def split_names(value: Any) -> list[str]:
    if isinstance(value, list):
        return [str(v).strip() for v in value if str(v).strip()]
    text = str(value or "").strip()
    if not text:
        return []
    parts: list[str] = []
    for piece in text.replace("；", ",").replace(";", ",").split(","):
        piece = piece.strip()
        if piece:
            parts.append(piece)
    return parts


def bool_payload(payload: dict[str, Any], key: str, default: bool = False) -> bool:
    value = payload.get(key, default)
    if isinstance(value, bool):
        return value
    if isinstance(value, str):
        return value.lower() in {"1", "true", "yes", "on", "y"}
    return bool(value)


def int_payload(payload: dict[str, Any], key: str, default: int) -> int:
    value = payload.get(key, default)
    try:
        return int(value)
    except Exception:
        return default


@contextlib.contextmanager
def patch_agent_logger(job: WebJob):
    original_log = agent._log

    def web_log(step: str, msg: str, level: str = "INFO") -> None:
        job.log(f"{step}: {msg}", level)

    agent._log = web_log
    try:
        yield
    finally:
        agent._log = original_log


def run_job(job: WebJob, payload: dict[str, Any]) -> None:
    with RUN_LOCK:
        job.status = "running"
        job.log("任务启动")
        try:
            with patch_agent_logger(job):
                items = load_items_from_payload(payload)
                job.log(f"已读取 {len(items)} 条输入")
                job.summary = {
                    "total": len(items),
                    "processed": 0,
                    "generated": 0,
                    "copied_auth_json": 0,
                    "failed": 0,
                    "stopped_remaining": len(items),
                    "ready_for_import": 0,
                    "sub_import": None,
                }

                out_dir = str(payload.get("out_dir") or "results").strip() or "results"
                verify_task = bool_payload(payload, "verify_task", True)
                sub_import_enabled = bool_payload(payload, "sub_import", False)
                has_sub_config = any(
                    str(payload.get(k) or "").strip()
                    for k in ("sub_url", "sub_email", "sub_password", "sub_group_ids", "sub_group_names")
                )
                job.log(f"运行配置：verify_task={verify_task}, sub_import={sub_import_enabled}")
                sub_client: agent.Sub2APIClient | None = None
                sub_group_ids: list[int] = []
                sub_concurrency = int_payload(payload, "sub_concurrency", agent.DEFAULT_SUB_CONCURRENCY)
                sub_priority = int_payload(payload, "sub_priority", agent.DEFAULT_SUB_PRIORITY)
                update_existing = bool_payload(payload, "update_existing", True)
                skip_default_group_bind = bool_payload(payload, "skip_default_group_bind", True)
                confirm_mixed_channel_risk = True if bool_payload(payload, "confirm_mixed_channel_risk", False) else None
                sub_test_accounts = bool_payload(payload, "sub_test_accounts", False)
                sub_import_acc = new_sub_import_accumulator()
                sub_account_tests_acc: list[dict[str, Any]] = []
                imported_content_count = 0

                if sub_import_enabled:
                    job.log("sub 导入已启用：注册成功一条，就立即导入 sub 一条。")
                    sub_url = str(payload.get("sub_url") or "").strip()
                    sub_email = str(payload.get("sub_email") or "").strip()
                    sub_password = str(payload.get("sub_password") or "")
                    if not sub_url or not sub_email or not sub_password:
                        raise RuntimeError("导入 sub 需要填写 sub 地址、管理员邮箱、密码")

                    sub_client = agent.Sub2APIClient(sub_url, sub_email, timeout=int_payload(payload, "sub_timeout", 30))
                    if bool_payload(payload, "sub_test_first", True):
                        test = sub_client.test_connection(sub_password)
                        if not test.get("ok"):
                            raise RuntimeError("sub 连接测试未通过")
                    else:
                        sub_client.login(sub_password)

                    sub_group_ids = sub_client.resolve_group_ids(
                        agent.parse_group_ids(split_names(payload.get("sub_group_ids"))),
                        split_names(payload.get("sub_group_names")),
                    )
                    job.log(f"sub 准备完成：group_ids={sub_group_ids}, concurrency={sub_concurrency}, priority={sub_priority}", "OK")
                elif has_sub_config:
                    job.log("检测到已填写 sub 信息，但 sub 导入开关未启用；本次只会本地生成 auth.json。", "WARN")
                else:
                    job.log("sub 导入未启用；本次只会本地生成 auth.json。")

                def on_progress(batch_run: agent.BatchRun) -> None:
                    nonlocal imported_content_count
                    job.run_dir = str(batch_run.run_dir)
                    job.auth_dir = str(batch_run.auth_dir)
                    job.summary_path = str(batch_run.summary_path or "")
                    job.csv_path = str(batch_run.csv_path or "")
                    job.payload_path = str(batch_run.payload_path or "")
                    job.errors_path = str(batch_run.errors_path or "")
                    job.summary = batch_live_summary(batch_run, len(items))
                    job.updated_at = time.time()

                    if not sub_import_enabled or sub_client is None or job.stop_requested:
                        return

                    successful_rows = [r for r in batch_run.results if r.get("status") == "success"]
                    while imported_content_count < len(batch_run.auth_contents) and not job.stop_requested:
                        content_pos = imported_content_count
                        content = batch_run.auth_contents[content_pos]
                        source_row = successful_rows[content_pos] if content_pos < len(successful_rows) else {}
                        batch_index = int(source_row.get("index") or content_pos + 1)
                        imported_content_count += 1

                        batch_run.write_sub_payload(
                            group_ids=sub_group_ids,
                            concurrency=sub_concurrency,
                            priority=sub_priority,
                            update_existing=update_existing,
                            skip_default_group_bind=skip_default_group_bind,
                            confirm_mixed_channel_risk=confirm_mixed_channel_risk,
                        )
                        job.payload_path = str(batch_run.payload_path or "")
                        job.log(f"立即导入 sub：batch_index={batch_index}, email={source_row.get('email', '')}")
                        try:
                            import_result = sub_client.import_codex_sessions(
                                [content],
                                group_ids=sub_group_ids,
                                concurrency=sub_concurrency,
                                priority=sub_priority,
                                update_existing=update_existing,
                                skip_default_group_bind=skip_default_group_bind,
                                confirm_mixed_channel_risk=confirm_mixed_channel_risk,
                            )
                            import_result["proxy_clear"] = sub_client.clear_imported_account_proxies(import_result)
                            merge_sub_import_result(sub_import_acc, import_result, batch_index=batch_index)
                            batch_run.sub_import_result = sub_import_acc
                            batch_run.sub_import_result_path = batch_run.run_dir / "sub_import_result.json"
                            agent.write_json(batch_run.sub_import_result_path, sub_import_acc)
                            job.sub_import_result_path = str(batch_run.sub_import_result_path)

                            if sub_test_accounts and not job.stop_requested:
                                tests = sub_client.test_imported_accounts(import_result)
                                for row in tests:
                                    row = dict(row)
                                    row["batch_index"] = batch_index
                                    sub_account_tests_acc.append(row)
                                batch_run.sub_account_tests = sub_account_tests_acc
                                batch_run.sub_account_tests_path = batch_run.run_dir / "sub_account_tests.json"
                                agent.write_json(batch_run.sub_account_tests_path, sub_account_tests_acc)
                                job.sub_account_tests_path = str(batch_run.sub_account_tests_path)
                        except Exception as import_exc:
                            record_sub_import_exception(sub_import_acc, str(import_exc), batch_index=batch_index)
                            batch_run.sub_import_result = sub_import_acc
                            batch_run.sub_import_result_path = batch_run.run_dir / "sub_import_result.json"
                            agent.write_json(batch_run.sub_import_result_path, sub_import_acc)
                            job.sub_import_result_path = str(batch_run.sub_import_result_path)
                            job.log(f"立即导入 sub 失败：batch_index={batch_index}, error={import_exc}", "ERROR")

                        job.summary = batch_live_summary(batch_run, len(items))
                        job.updated_at = time.time()

                batch = agent.BatchProcessor(out_dir, verify_task=verify_task)
                batch_run = batch.process(
                    items,
                    progress_callback=on_progress,
                    cancel_check=lambda: job.stop_requested,
                )

                job.run_dir = str(batch_run.run_dir)
                job.auth_dir = str(batch_run.auth_dir)
                job.summary_path = str(batch_run.summary_path or "")
                job.csv_path = str(batch_run.csv_path or "")
                job.payload_path = str(batch_run.payload_path or "")
                job.errors_path = str(batch_run.errors_path or "")

                if job.stop_requested:
                    job.status = "stopped"
                    job.finished_at = time.time()
                    job.updated_at = time.time()
                    job.log("任务已停止；后续输入不会继续注册，也不会继续导入 sub。", "WARN")
                elif sub_import_enabled:
                    batch_run.sub_import_result = sub_import_acc
                    batch_run.sub_import_result_path = batch_run.run_dir / "sub_import_result.json"
                    agent.write_json(batch_run.sub_import_result_path, sub_import_acc)
                    job.sub_import_result_path = str(batch_run.sub_import_result_path)
                    if sub_account_tests_acc:
                        batch_run.sub_account_tests = sub_account_tests_acc
                        batch_run.sub_account_tests_path = batch_run.run_dir / "sub_account_tests.json"
                        agent.write_json(batch_run.sub_account_tests_path, sub_account_tests_acc)
                        job.sub_account_tests_path = str(batch_run.sub_account_tests_path)
                    job.log(
                        "即时导入完成："
                        f"total={sub_import_acc.get('total', 0)} created={sub_import_acc.get('created', 0)} "
                        f"updated={sub_import_acc.get('updated', 0)} skipped={sub_import_acc.get('skipped', 0)} "
                        f"failed={sub_import_acc.get('failed', 0)} "
                        f"proxy_cleared={sum(1 for x in sub_import_acc.get('proxy_clear', []) if isinstance(x, dict) and x.get('success') is True)}",
                        "OK" if int(sub_import_acc.get("failed", 0) or 0) == 0 else "WARN",
                    )

                batch_run.write_summary()
                job.summary_path = str(batch_run.summary_path or "")
                job.csv_path = str(batch_run.csv_path or "")

                if batch_run.summary_path and Path(batch_run.summary_path).exists():
                    job.summary = json.loads(Path(batch_run.summary_path).read_text(encoding="utf-8"))

                if job.status != "stopped":
                    job.status = "finished"
                job.finished_at = time.time()
                job.updated_at = time.time()
                job.log("任务已停止", "WARN") if job.status == "stopped" else job.log("任务完成", "OK")
        except Exception as exc:
            job.status = "failed"
            job.error = agent.redact_text(str(exc))
            job.finished_at = time.time()
            job.updated_at = time.time()
            job.log(f"任务失败: {exc}", "ERROR")
            job.log(traceback.format_exc(), "ERROR")


def start_web_job(payload: dict[str, Any]) -> WebJob:
    if RUN_LOCK.locked():
        raise RuntimeError("已有任务正在运行，请等待完成后再启动新任务")
    job_id = uuid.uuid4().hex[:12]
    job = WebJob(id=job_id)
    with JOBS_LOCK:
        JOBS[job_id] = job
    t = threading.Thread(target=run_job, args=(job, payload), daemon=True)
    t.start()
    return job


def get_job(job_id: str) -> WebJob:
    with JOBS_LOCK:
        job = JOBS.get(job_id)
    if not job:
        raise KeyError(job_id)
    return job


def batch_live_summary(batch_run: agent.BatchRun, total_items: int) -> dict[str, Any]:
    processed = len(batch_run.results)
    generated = sum(1 for r in batch_run.results if r.get("status") == "success" and r.get("kind") != "auth_json")
    copied = sum(1 for r in batch_run.results if r.get("status") == "success" and r.get("kind") == "auth_json")
    failed = sum(1 for r in batch_run.results if r.get("status") != "success")
    return {
        "total": total_items,
        "processed": processed,
        "generated": generated,
        "copied_auth_json": copied,
        "failed": failed,
        "stopped_remaining": max(total_items - processed, 0),
        "ready_for_import": len(batch_run.auth_contents),
        "run_dir": str(batch_run.run_dir),
        "auth_dir": str(batch_run.auth_dir),
        "sub_import_payload": str(batch_run.payload_path) if batch_run.payload_path else "",
        "sub_import": (
            {
                "total": batch_run.sub_import_result.get("total", 0),
                "created": batch_run.sub_import_result.get("created", 0),
                "updated": batch_run.sub_import_result.get("updated", 0),
                "skipped": batch_run.sub_import_result.get("skipped", 0),
                "failed": batch_run.sub_import_result.get("failed", 0),
                "proxy_cleared": sum(
                    1
                    for x in (batch_run.sub_import_result.get("proxy_clear") or [])
                    if isinstance(x, dict) and x.get("success") is True
                ),
                "proxy_clear_failed": sum(
                    1
                    for x in (batch_run.sub_import_result.get("proxy_clear") or [])
                    if isinstance(x, dict) and x.get("success") is not True
                ),
            }
            if batch_run.sub_import_result
            else None
        ),
    }


def new_sub_import_accumulator() -> dict[str, Any]:
    return {
        "total": 0,
        "created": 0,
        "updated": 0,
        "skipped": 0,
        "failed": 0,
        "items": [],
        "warnings": [],
        "errors": [],
        "proxy_clear": [],
    }


def merge_sub_import_result(acc: dict[str, Any], result: dict[str, Any], *, batch_index: int | None = None) -> dict[str, Any]:
    for key in ("total", "created", "updated", "skipped", "failed"):
        acc[key] = int(acc.get(key, 0) or 0) + int(result.get(key, 0) or 0)
    for key in ("items", "warnings", "errors"):
        values = result.get(key) or []
        if isinstance(values, list):
            for value in values:
                if isinstance(value, dict) and batch_index is not None:
                    value = dict(value)
                    value["batch_index"] = batch_index
                acc.setdefault(key, []).append(value)
    proxy_values = result.get("proxy_clear") or []
    if isinstance(proxy_values, list):
        for value in proxy_values:
            if isinstance(value, dict) and batch_index is not None:
                value = dict(value)
                value["batch_index"] = batch_index
            acc.setdefault("proxy_clear", []).append(value)
    return acc


def record_sub_import_exception(acc: dict[str, Any], message: str, *, batch_index: int | None = None) -> dict[str, Any]:
    acc["total"] = int(acc.get("total", 0) or 0) + 1
    acc["failed"] = int(acc.get("failed", 0) or 0) + 1
    row = {"index": batch_index or acc["total"], "batch_index": batch_index, "message": agent.redact_text(message)}
    acc.setdefault("items", []).append({"index": row["index"], "batch_index": batch_index, "action": "failed", "message": row["message"]})
    acc.setdefault("errors", []).append(row)
    return acc


def allowed_job_file(job: WebJob, name: str) -> Path:
    allowed = {
        "summary.json": job.summary_path,
        "summary.csv": job.csv_path,
        "sub_import_payload.json": job.payload_path,
        "errors.jsonl": job.errors_path,
        "sub_import_result.json": job.sub_import_result_path,
        "sub_account_tests.json": job.sub_account_tests_path,
    }
    raw = allowed.get(name)
    if not raw:
        raise FileNotFoundError(name)
    path = Path(raw)
    if not path.exists():
        raise FileNotFoundError(name)
    return path


def make_sub_client_from_payload(payload: dict[str, Any]) -> agent.Sub2APIClient:
    sub_url = str(payload.get("sub_url") or "").strip()
    sub_email = str(payload.get("sub_email") or "").strip()
    if not sub_url or not sub_email:
        raise RuntimeError("请填写 sub 地址和管理员邮箱")
    return agent.Sub2APIClient(sub_url, sub_email, timeout=int_payload(payload, "sub_timeout", 30))


class CodexAgentWebHandler(BaseHTTPRequestHandler):
    server_version = "CodexAgentWeb/1.0"

    def log_message(self, fmt: str, *args: Any) -> None:
        print(f"{self.address_string()} - {fmt % args}")

    def do_GET(self) -> None:
        parsed = urlparse(self.path)
        path = parsed.path
        try:
            if path == "/":
                return send_text(self, INDEX_HTML, "text/html; charset=utf-8")
            if path == "/assets/qr_group.png":
                if not QR_GROUP_IMAGE.exists():
                    return send_json(self, {"ok": False, "error": "qr image not found"}, HTTPStatus.NOT_FOUND)
                return send_file(self, QR_GROUP_IMAGE, "image/png")
            if path == "/api/health":
                return send_json(self, {"ok": True, "time": time.time()})
            if path.startswith("/api/job/"):
                parts = [unquote(p) for p in path.strip("/").split("/")]
                # /api/job/:id
                if len(parts) == 3:
                    job = get_job(parts[2])
                    return send_json(self, {"ok": True, "job": job.to_dict()})
                # /api/job/:id/file/:name
                if len(parts) == 5 and parts[3] == "file":
                    job = get_job(parts[2])
                    file_path = allowed_job_file(job, parts[4])
                    content_type = "application/json; charset=utf-8" if file_path.suffix == ".json" else "text/plain; charset=utf-8"
                    if file_path.suffix == ".csv":
                        content_type = "text/csv; charset=utf-8"
                    return send_file(self, file_path, content_type)
            return send_json(self, {"ok": False, "error": "not found"}, HTTPStatus.NOT_FOUND)
        except Exception as exc:
            return send_json(self, {"ok": False, "error": agent.redact_text(str(exc))}, HTTPStatus.INTERNAL_SERVER_ERROR)

    def do_POST(self) -> None:
        parsed = urlparse(self.path)
        path = parsed.path
        try:
            payload = read_json_body(self)
            if path == "/api/run":
                job = start_web_job(payload)
                return send_json(self, {"ok": True, "job_id": job.id, "job": job.to_dict()})

            if path == "/api/sub/test":
                client = make_sub_client_from_payload(payload)
                password = str(payload.get("sub_password") or "")
                if not password:
                    raise RuntimeError("请填写 sub 管理员密码")
                result = client.test_connection(password)
                return send_json(self, {"ok": bool(result.get("ok")), "result": result})

            if path == "/api/sub/groups":
                client = make_sub_client_from_payload(payload)
                password = str(payload.get("sub_password") or "")
                if not password:
                    raise RuntimeError("请填写 sub 管理员密码")
                client.login(password)
                groups = client.list_groups()
                return send_json(self, {"ok": True, "groups": groups})

            if path.startswith("/api/job/") and path.endswith("/open-dir"):
                parts = [unquote(p) for p in path.strip("/").split("/")]
                job = get_job(parts[2])
                if not job.run_dir or not Path(job.run_dir).exists():
                    raise RuntimeError("结果目录还不存在")
                os.startfile(job.run_dir)  # type: ignore[attr-defined]
                return send_json(self, {"ok": True})

            if path.startswith("/api/job/") and path.endswith("/stop"):
                parts = [unquote(p) for p in path.strip("/").split("/")]
                job = get_job(parts[2])
                if job.status in {"finished", "failed", "stopped"}:
                    return send_json(self, {"ok": True, "job": job.to_dict(), "message": "任务已结束"})
                job.request_stop()
                return send_json(self, {"ok": True, "job": job.to_dict()})

            return send_json(self, {"ok": False, "error": "not found"}, HTTPStatus.NOT_FOUND)
        except Exception as exc:
            return send_json(self, {"ok": False, "error": agent.redact_text(str(exc))}, HTTPStatus.BAD_REQUEST)


INDEX_HTML = r"""<!doctype html>
<html lang="zh-CN">
<head>
  <meta charset="utf-8" />
  <meta name="viewport" content="width=device-width, initial-scale=1" />
  <title>Codex Agent Identity · Batch Console</title>
  <style>
    :root{
      --bg:#070b16; --panel:#0f172a; --panel2:#111827; --soft:#1f2937;
      --line:rgba(148,163,184,.18); --text:#e5e7eb; --muted:#94a3b8;
      --blue:#3b82f6; --indigo:#6366f1; --cyan:#06b6d4; --green:#10b981;
      --red:#ef4444; --amber:#f59e0b; --shadow:0 22px 70px rgba(0,0,0,.35);
    }
    *{box-sizing:border-box}
    body{
      margin:0; min-height:100vh; color:var(--text);
      font-family:Inter, ui-sans-serif, system-ui, -apple-system, BlinkMacSystemFont, "Segoe UI", "Microsoft YaHei", sans-serif;
      background:
        radial-gradient(circle at 12% 5%, rgba(59,130,246,.22), transparent 28rem),
        radial-gradient(circle at 88% 6%, rgba(99,102,241,.20), transparent 30rem),
        linear-gradient(180deg,#060914 0%,#0b1020 45%,#060914 100%);
    }
    a{color:#93c5fd;text-decoration:none}
    .app{display:grid; grid-template-columns:270px minmax(0,1fr); min-height:100vh}
    .sidebar{
      position:sticky; top:0; height:100vh; padding:22px 18px;
      background:linear-gradient(180deg,rgba(15,23,42,.92),rgba(2,6,23,.86));
      border-right:1px solid var(--line); backdrop-filter:blur(18px);
    }
    .brand{display:flex; align-items:center; gap:12px; padding:8px 10px 24px}
    .logo{
      width:42px;height:42px;border-radius:15px;
      background:linear-gradient(135deg,var(--blue),var(--indigo) 58%,var(--cyan));
      box-shadow:0 14px 30px rgba(59,130,246,.28);
      display:grid;place-items:center;font-weight:900;color:#fff;
    }
    .brand-title{font-weight:800;font-size:16px;line-height:1.15}
    .brand-sub{font-size:12px;color:var(--muted);margin-top:3px}
    .nav-title{padding:18px 12px 8px;color:#64748b;font-size:11px;text-transform:uppercase;letter-spacing:.12em}
    .nav-item{
      display:flex;align-items:center;gap:11px;padding:11px 12px;border-radius:14px;
      color:#cbd5e1;margin:4px 0;border:1px solid transparent;
    }
    .nav-item.active,.nav-item:hover{
      background:rgba(59,130,246,.12); border-color:rgba(59,130,246,.18); color:#fff;
    }
    .nav-dot{width:9px;height:9px;border-radius:50%;background:linear-gradient(135deg,var(--blue),var(--cyan))}
    .side-card{
      margin-top:24px;padding:15px;border-radius:18px;
      background:linear-gradient(180deg,rgba(30,41,59,.72),rgba(15,23,42,.62));
      border:1px solid var(--line); color:var(--muted);font-size:12px;line-height:1.7;
    }
    .main{padding:28px 34px 44px; min-width:0}
    .topbar{display:flex;align-items:flex-start;justify-content:space-between;gap:16px;margin-bottom:24px}
    h1{margin:0;font-size:30px;letter-spacing:-.04em}
    .subtitle{margin-top:8px;color:var(--muted);font-size:14px}
    .pill{
      display:inline-flex;align-items:center;gap:8px;padding:9px 13px;border-radius:999px;
      color:#bfdbfe;background:rgba(59,130,246,.12);border:1px solid rgba(59,130,246,.22);
      font-size:12px;white-space:nowrap;
    }
    .grid{display:grid;grid-template-columns:1.22fr .78fr;gap:18px}
    .full{grid-column:1 / -1}
    .cards{display:grid;grid-template-columns:repeat(4,minmax(0,1fr));gap:14px;margin-bottom:18px}
    .stat,.card{
      border:1px solid var(--line); background:linear-gradient(180deg,rgba(15,23,42,.76),rgba(15,23,42,.58));
      box-shadow:var(--shadow); border-radius:22px; backdrop-filter:blur(18px);
    }
    .stat{padding:17px 18px}
    .stat .label{font-size:12px;color:var(--muted)}
    .stat .value{font-size:27px;font-weight:800;margin-top:6px}
    .card{overflow:hidden}
    .card-head{display:flex;justify-content:space-between;align-items:center;gap:10px;padding:18px 20px;border-bottom:1px solid var(--line)}
    .card-title{font-weight:800}
    .card-desc{font-size:12px;color:var(--muted);margin-top:4px}
    .card-body{padding:20px}
    label{display:block;font-size:13px;color:#cbd5e1;margin:0 0 8px;font-weight:650}
    .hint{color:var(--muted);font-size:12px;line-height:1.55;margin-top:7px}
    textarea,input,select{
      width:100%;border:1px solid rgba(148,163,184,.22);outline:none;color:#e5e7eb;
      background:rgba(2,6,23,.48);border-radius:14px;padding:12px 13px;
      transition:.18s border,.18s box-shadow,.18s background;font-size:13px;
    }
    textarea{min-height:245px;resize:vertical;font-family:ui-monospace,SFMono-Regular,Consolas,"Liberation Mono",monospace;line-height:1.55}
    input:focus,textarea:focus,select:focus{border-color:rgba(59,130,246,.72);box-shadow:0 0 0 4px rgba(59,130,246,.14);background:rgba(2,6,23,.72)}
    .row{display:grid;grid-template-columns:1fr 1fr;gap:12px}
    .row3{display:grid;grid-template-columns:1fr 1fr 1fr;gap:12px}
    .field{margin-bottom:14px}
    .checks{display:grid;grid-template-columns:1fr 1fr;gap:10px}
    .check{
      display:flex;gap:10px;align-items:flex-start;border:1px solid var(--line);border-radius:14px;padding:11px;background:rgba(15,23,42,.45);
      color:#d1d5db;font-size:13px;
    }
    .check input{width:16px;height:16px;margin-top:1px;accent-color:#3b82f6}
    .btns{display:flex;flex-wrap:wrap;gap:10px;align-items:center}
    button{
      border:0;cursor:pointer;border-radius:14px;padding:11px 15px;color:#fff;font-weight:750;
      transition:.18s transform,.18s filter,.18s opacity;display:inline-flex;gap:9px;align-items:center;justify-content:center;
    }
    button:hover{transform:translateY(-1px);filter:brightness(1.04)}
    button:disabled{opacity:.55;cursor:not-allowed;transform:none}
    .primary{background:linear-gradient(135deg,var(--blue),var(--indigo));box-shadow:0 12px 30px rgba(59,130,246,.25)}
    .success{background:linear-gradient(135deg,#10b981,#059669);box-shadow:0 12px 30px rgba(16,185,129,.20)}
    .secondary{background:rgba(30,41,59,.9);border:1px solid var(--line)}
    .warning{background:linear-gradient(135deg,#f59e0b,#d97706)}
    .danger{background:linear-gradient(135deg,#ef4444,#dc2626)}
    .status{
      display:inline-flex;align-items:center;gap:8px;padding:7px 10px;border-radius:999px;
      border:1px solid var(--line);font-size:12px;color:#cbd5e1;background:rgba(15,23,42,.5);
    }
    .status-dot{width:8px;height:8px;border-radius:50%;background:#64748b}
    .status.running .status-dot{background:var(--amber);box-shadow:0 0 0 5px rgba(245,158,11,.15)}
    .status.stopping .status-dot{background:var(--amber);box-shadow:0 0 0 5px rgba(245,158,11,.15)}
    .status.finished .status-dot{background:var(--green);box-shadow:0 0 0 5px rgba(16,185,129,.12)}
    .status.stopped .status-dot{background:#64748b;box-shadow:0 0 0 5px rgba(148,163,184,.12)}
    .status.failed .status-dot{background:var(--red);box-shadow:0 0 0 5px rgba(239,68,68,.12)}
    pre{
      margin:0;min-height:260px;max-height:410px;overflow:auto;padding:16px;border-radius:16px;
      background:#020617;border:1px solid rgba(148,163,184,.18);color:#cbd5e1;font-size:12px;line-height:1.55;
    }
    .groups{display:flex;flex-wrap:wrap;gap:9px;max-height:210px;overflow:auto;padding-right:4px}
    .group-badge{
      border:1px solid rgba(59,130,246,.25);background:rgba(59,130,246,.10);
      color:#bfdbfe;border-radius:999px;padding:7px 10px;font-size:12px;
    }
    .result-list{display:grid;gap:10px}
    .result-item{
      display:flex;justify-content:space-between;gap:12px;align-items:center;padding:12px;border-radius:14px;
      border:1px solid var(--line);background:rgba(2,6,23,.35);font-size:13px;
    }
    .path{color:#93c5fd;overflow:hidden;text-overflow:ellipsis;white-space:nowrap;max-width:66vw}
    .toast{
      position:fixed;right:22px;bottom:22px;z-index:50;display:none;max-width:520px;
      padding:14px 16px;border-radius:16px;border:1px solid var(--line);background:rgba(15,23,42,.96);
      box-shadow:var(--shadow);color:#e5e7eb;font-size:13px;
    }
    .toast.show{display:block}
    .qr-modal{
      position:fixed;inset:0;z-index:80;display:none;align-items:center;justify-content:center;
      padding:24px;background:rgba(2,6,23,.72);backdrop-filter:blur(14px);
    }
    .qr-modal.show{display:flex}
    .qr-dialog{
      width:min(420px,calc(100vw - 42px));border-radius:28px;overflow:hidden;
      background:linear-gradient(180deg,rgba(15,23,42,.98),rgba(2,6,23,.98));
      border:1px solid rgba(148,163,184,.25);box-shadow:0 30px 90px rgba(0,0,0,.55);
      animation:modalIn .18s ease-out;
    }
    @keyframes modalIn{from{opacity:0;transform:translateY(10px) scale(.98)}to{opacity:1;transform:translateY(0) scale(1)}}
    .qr-head{display:flex;align-items:center;justify-content:space-between;gap:12px;padding:18px 20px;border-bottom:1px solid var(--line)}
    .qr-title{font-size:17px;font-weight:850}
    .qr-close{
      width:34px;height:34px;border-radius:12px;padding:0;background:rgba(30,41,59,.85);
      border:1px solid var(--line);font-size:20px;line-height:1;color:#cbd5e1;
    }
    .qr-body{padding:22px;text-align:center}
    .qr-img{
      width:min(260px,82vw);height:auto;border-radius:16px;background:#fff;padding:0;
      box-shadow:0 18px 45px rgba(59,130,246,.16);
    }
    .qr-tip{margin-top:14px;color:var(--muted);font-size:13px;line-height:1.6}
    .badge{font-size:11px;border-radius:999px;padding:4px 8px;background:rgba(148,163,184,.12);color:#cbd5e1;border:1px solid var(--line)}
    .muted{color:var(--muted)}
    @media (max-width:1100px){.app{grid-template-columns:1fr}.sidebar{display:none}.grid,.cards{grid-template-columns:1fr}.main{padding:22px}.row,.row3,.checks{grid-template-columns:1fr}}
  </style>
</head>
<body>
  <div class="app">
    <aside class="sidebar">
      <div class="brand">
        <div class="logo">C</div>
        <div>
          <div class="brand-title">Codex Agent</div>
          <div class="brand-sub">Batch Identity Console</div>
        </div>
      </div>
      <div class="nav-title">Admin</div>
      <a class="nav-item active" href="#batch"><span class="nav-dot"></span>批量生成</a>
      <a class="nav-item" href="#sub"><span class="nav-dot"></span>Sub2API 导入</a>
      <a class="nav-item" href="#result"><span class="nav-dot"></span>运行结果</a>
      <div class="nav-title">Security</div>
      <div class="side-card">
        <b>本地面板</b><br>
        页面只连接本机服务。AT 日志会脱敏；生成结果里的 agent_private_key 属于敏感内容，结果目录已加入 .gitignore。
      </div>
    </aside>

    <main class="main">
      <div class="topbar">
        <div>
          <h1>Codex Agent Identity 批量工具</h1>
          <div class="subtitle">批量导入 AT / session.json，注册 Agent Identity，导出 auth.json，并可直接导入 sub2api 分组。</div>
        </div>
        <div class="pill"><span>●</span> Local Web UI · Sub Style</div>
      </div>

      <section class="cards">
        <div class="stat"><div class="label">总数</div><div id="statTotal" class="value">0</div></div>
        <div class="stat"><div class="label">生成</div><div id="statGenerated" class="value">0</div></div>
        <div class="stat"><div class="label">失败</div><div id="statFailed" class="value">0</div></div>
        <div class="stat"><div class="label">Sub 导入</div><div id="statSub" class="value">-</div></div>
      </section>

      <section class="grid" id="batch">
        <div class="card">
          <div class="card-head">
            <div>
              <div class="card-title">1. 批量输入</div>
              <div class="card-desc">支持 tokens.txt / sessions.json / auth.json 内容。上传文件会在浏览器内读取并填入文本框。</div>
            </div>
            <span class="badge">AT 不完整显示</span>
          </div>
          <div class="card-body">
            <div class="field">
              <label>上传 tokens.txt / sessions.json / auth.json</label>
              <input id="fileInput" type="file" multiple />
              <div class="hint">多文件会自动合并到下面文本框；也可以直接粘贴。</div>
            </div>
            <div class="field">
              <label>粘贴内容</label>
              <textarea id="tokensText" placeholder="一行一个 accessToken，或粘贴 sessions.json / auth.json / sub_import_payload.json"></textarea>
            </div>
            <div class="row">
              <div class="field">
                <label>服务器输入路径（可选）</label>
                <input id="inputPath" placeholder="例如 C:\path\tokens.txt 或某个目录" />
              </div>
              <div class="field">
                <label>输出目录</label>
                <input id="outDir" value="results" />
              </div>
            </div>
            <div class="checks">
              <label class="check"><input id="verifyTask" type="checkbox" checked><span>生成后验证 task 注册</span></label>
              <label class="check"><input id="subImport" type="checkbox"><span>注册成功后立即导入 sub2api</span></label>
            </div>
          </div>
        </div>

        <div class="card" id="sub">
          <div class="card-head">
            <div>
              <div class="card-title">2. Sub2API 连接</div>
              <div class="card-desc">填写地址、管理员账号、密码；密码只用于本次请求。</div>
            </div>
            <span id="subStatus" class="status"><span class="status-dot"></span>未测试</span>
          </div>
          <div class="card-body">
            <div class="field">
              <label class="check" style="border-color:rgba(59,130,246,.35);background:rgba(59,130,246,.10)">
                <input id="subImport2" type="checkbox">
                <span><b>注册成功后立即导入 sub2api</b><br><span class="hint">每条 auth.json 生成成功后，会立刻调用 sub 导入接口；失败项跳过。</span></span>
              </label>
            </div>
            <div class="field">
              <label>Sub 地址</label>
              <input id="subUrl" placeholder="https://你的sub地址" />
            </div>
            <div class="field">
              <label>管理员邮箱</label>
              <input id="subEmail" placeholder="admin@example.com" />
            </div>
            <div class="field">
              <label>管理员密码</label>
              <input id="subPassword" type="password" placeholder="Sub password" />
            </div>
            <div class="row">
              <div class="field">
                <label>分组 ID</label>
                <input id="subGroupIds" placeholder="3 或 1,2" />
              </div>
              <div class="field">
                <label>分组名</label>
                <input id="subGroupNames" placeholder="Codex分组" />
              </div>
            </div>
            <div class="row3">
              <div class="field">
                <label>并发</label>
                <input id="subConcurrency" type="number" value="3" min="0" />
              </div>
              <div class="field">
                <label>优先级</label>
                <input id="subPriority" type="number" value="50" min="0" />
              </div>
              <div class="field">
                <label>超时秒</label>
                <input id="subTimeout" type="number" value="30" min="1" />
              </div>
            </div>
            <div class="checks">
              <label class="check"><input id="subTestFirst" type="checkbox" checked><span>导入前测试 sub 连接</span></label>
              <label class="check"><input id="subTestAccounts" type="checkbox"><span>导入后测试账号</span></label>
              <label class="check"><input id="updateExisting" type="checkbox" checked><span>更新已有账号</span></label>
              <label class="check"><input id="skipDefaultGroupBind" type="checkbox" checked><span>跳过默认分组绑定</span></label>
            </div>
            <div class="btns" style="margin-top:14px">
              <button class="secondary" onclick="testSub()">测试连接</button>
              <button class="secondary" onclick="loadGroups()">读取分组</button>
              <button class="success" onclick="saveSubConfig()">保存配置</button>
              <button class="secondary" onclick="clearSubConfig()">清除保存</button>
              <button class="primary" onclick="startRun()">开始生成 / 导入</button>
              <button id="stopBtn" class="danger" onclick="stopRun()" disabled>停止任务</button>
            </div>
            <div class="hint">保存配置会写入本机浏览器 localStorage；只保存 sub 配置和选项，不保存 AT/粘贴内容。</div>
          </div>
        </div>

        <div class="card full">
          <div class="card-head">
            <div>
              <div class="card-title">3. 分组列表</div>
              <div class="card-desc">读取 `/api/v1/admin/groups/all` 后显示，可按 ID 或名称导入。</div>
            </div>
          </div>
          <div class="card-body">
            <div id="groups" class="groups muted">尚未读取分组</div>
          </div>
        </div>

        <div class="card full" id="result">
          <div class="card-head">
            <div>
              <div class="card-title">4. 运行日志</div>
              <div class="card-desc">后台串行生成，避免注册接口被并发请求触发限流。</div>
            </div>
            <span id="jobStatus" class="status"><span class="status-dot"></span>Idle</span>
          </div>
          <div class="card-body">
            <pre id="logs">等待任务...</pre>
          </div>
        </div>

        <div class="card full">
          <div class="card-head">
            <div>
              <div class="card-title">5. 结果文件</div>
              <div class="card-desc">生成完成后可下载 summary / payload，也可以打开结果目录。</div>
            </div>
            <div class="btns">
              <button class="secondary" onclick="openRunDir()">打开结果目录</button>
            </div>
          </div>
          <div class="card-body">
            <div id="resultFiles" class="result-list muted">暂无结果</div>
          </div>
        </div>
      </section>
    </main>
  </div>
  <div id="qrModal" class="qr-modal" onclick="modalBackdropClose(event)">
    <div class="qr-dialog" role="dialog" aria-modal="true" aria-labelledby="qrTitle">
      <div class="qr-head">
        <div>
          <div id="qrTitle" class="qr-title">熊猫GPT交流</div>
          <div class="card-desc">扫码加入交流群</div>
        </div>
        <button class="qr-close" onclick="closeQrModal()" aria-label="关闭">×</button>
      </div>
      <div class="qr-body">
        <img class="qr-img" src="/assets/qr_group.png" alt="熊猫GPT交流群二维码" />
        <div class="qr-tip">群号：1106538918</div>
      </div>
    </div>
  </div>
  <div id="toast" class="toast"></div>

  <script>
    let currentJobId = null;
    let pollTimer = null;

    const $ = (id) => document.getElementById(id);
    const val = (id) => $(id).value.trim();
    const checked = (id) => $(id).checked;
    const SUB_CONFIG_KEY = 'codexAgentWeb.subConfig.v1';

    window.addEventListener('DOMContentLoaded', () => {
      loadSavedSubConfig();
      setTimeout(openQrModal, 260);
    });
    window.addEventListener('keydown', (ev) => {
      if(ev.key === 'Escape') closeQrModal();
    });

    function openQrModal(){
      $('qrModal')?.classList.add('show');
    }
    function closeQrModal(){
      $('qrModal')?.classList.remove('show');
    }
    function modalBackdropClose(ev){
      if(ev.target && ev.target.id === 'qrModal') closeQrModal();
    }

    function toast(message, danger=false){
      const el = $('toast');
      el.textContent = message;
      el.style.borderColor = danger ? 'rgba(239,68,68,.45)' : 'rgba(59,130,246,.35)';
      el.classList.add('show');
      setTimeout(()=>el.classList.remove('show'), 4200);
    }

    async function api(path, data){
      const res = await fetch(path, {
        method:'POST',
        headers:{'Content-Type':'application/json'},
        body: JSON.stringify(data || {})
      });
      const body = await res.json().catch(()=>({ok:false,error:'响应不是 JSON'}));
      if(!res.ok || body.ok === false){
        throw new Error(body.error || ('HTTP '+res.status));
      }
      return body;
    }

    $('fileInput').addEventListener('change', async (ev)=>{
      const files = Array.from(ev.target.files || []);
      if(!files.length) return;
      const chunks = [];
      for(const file of files){
        chunks.push('# ===== '+file.name+' =====');
        chunks.push(await file.text());
      }
      const old = $('tokensText').value.trim();
      $('tokensText').value = (old ? old + '\n' : '') + chunks.join('\n');
      toast('已读取 '+files.length+' 个文件');
    });

    function syncSubImport(v){
      $('subImport').checked = v;
      $('subImport2').checked = v;
    }
    $('subImport').addEventListener('change', () => syncSubImport($('subImport').checked));
    $('subImport2').addEventListener('change', () => syncSubImport($('subImport2').checked));

    function collectSubConfig(){
      return {
        sub_import: checked('subImport') || checked('subImport2'),
        sub_url: val('subUrl'),
        sub_email: val('subEmail'),
        sub_password: $('subPassword').value,
        sub_group_ids: val('subGroupIds'),
        sub_group_names: val('subGroupNames'),
        sub_concurrency: val('subConcurrency') || '3',
        sub_priority: val('subPriority') || '50',
        sub_timeout: val('subTimeout') || '30',
        sub_test_first: checked('subTestFirst'),
        sub_test_accounts: checked('subTestAccounts'),
        update_existing: checked('updateExisting'),
        skip_default_group_bind: checked('skipDefaultGroupBind'),
        saved_at: new Date().toISOString()
      };
    }

    function applySubConfig(cfg){
      if(!cfg || typeof cfg !== 'object') return;
      if(cfg.sub_url !== undefined) $('subUrl').value = cfg.sub_url || '';
      if(cfg.sub_email !== undefined) $('subEmail').value = cfg.sub_email || '';
      if(cfg.sub_password !== undefined) $('subPassword').value = cfg.sub_password || '';
      if(cfg.sub_group_ids !== undefined) $('subGroupIds').value = cfg.sub_group_ids || '';
      if(cfg.sub_group_names !== undefined) $('subGroupNames').value = cfg.sub_group_names || '';
      if(cfg.sub_concurrency !== undefined) $('subConcurrency').value = cfg.sub_concurrency || '3';
      if(cfg.sub_priority !== undefined) $('subPriority').value = cfg.sub_priority || '50';
      if(cfg.sub_timeout !== undefined) $('subTimeout').value = cfg.sub_timeout || '30';
      if(cfg.sub_test_first !== undefined) $('subTestFirst').checked = !!cfg.sub_test_first;
      if(cfg.sub_test_accounts !== undefined) $('subTestAccounts').checked = !!cfg.sub_test_accounts;
      if(cfg.update_existing !== undefined) $('updateExisting').checked = !!cfg.update_existing;
      if(cfg.skip_default_group_bind !== undefined) $('skipDefaultGroupBind').checked = !!cfg.skip_default_group_bind;
      if(cfg.sub_import !== undefined) syncSubImport(!!cfg.sub_import);
    }

    function saveSubConfig(){
      try{
        const cfg = collectSubConfig();
        localStorage.setItem(SUB_CONFIG_KEY, JSON.stringify(cfg));
        toast('sub 配置已保存，下次打开会自动回填');
      }catch(e){
        toast('保存失败：' + e.message, true);
      }
    }

    function loadSavedSubConfig(){
      try{
        const raw = localStorage.getItem(SUB_CONFIG_KEY);
        if(!raw) return;
        applySubConfig(JSON.parse(raw));
        toast('已自动加载上次保存的 sub 配置');
      }catch(e){
        toast('读取保存配置失败：' + e.message, true);
      }
    }

    function clearSubConfig(){
      try{
        localStorage.removeItem(SUB_CONFIG_KEY);
        toast('已清除保存的 sub 配置');
      }catch(e){
        toast('清除失败：' + e.message, true);
      }
    }

    function payload(){
      return {
        tokens_text: $('tokensText').value,
        input_path: val('inputPath'),
        out_dir: val('outDir') || 'results',
        verify_task: checked('verifyTask'),
        sub_import: checked('subImport') || checked('subImport2'),
        sub_url: val('subUrl'),
        sub_email: val('subEmail'),
        sub_password: $('subPassword').value,
        sub_group_ids: val('subGroupIds'),
        sub_group_names: val('subGroupNames'),
        sub_concurrency: Number(val('subConcurrency') || 3),
        sub_priority: Number(val('subPriority') || 50),
        sub_timeout: Number(val('subTimeout') || 30),
        sub_test_first: checked('subTestFirst'),
        sub_test_accounts: checked('subTestAccounts'),
        update_existing: checked('updateExisting'),
        skip_default_group_bind: checked('skipDefaultGroupBind')
      };
    }

    async function testSub(){
      try{
        $('subStatus').className = 'status running';
        $('subStatus').innerHTML = '<span class="status-dot"></span>测试中';
        const data = await api('/api/sub/test', payload());
        $('subStatus').className = data.ok ? 'status finished' : 'status failed';
        $('subStatus').innerHTML = '<span class="status-dot"></span>' + (data.ok ? '连接可用' : '连接失败');
        toast(data.ok ? 'Sub 连接测试通过' : 'Sub 连接测试失败', !data.ok);
      }catch(e){
        $('subStatus').className = 'status failed';
        $('subStatus').innerHTML = '<span class="status-dot"></span>连接失败';
        toast(e.message, true);
      }
    }

    async function loadGroups(){
      try{
        const data = await api('/api/sub/groups', payload());
        const groups = data.groups || [];
        $('groups').classList.remove('muted');
        $('groups').innerHTML = groups.length ? groups.map(g=>{
          const id = g.id ?? g.ID ?? '';
          const name = g.name ?? g.display_name ?? '';
          const platform = g.platform ? ' · '+g.platform : '';
          const status = g.status ? ' · '+g.status : '';
          return `<span class="group-badge">#${id} ${escapeHtml(name)}${escapeHtml(platform)}${escapeHtml(status)}</span>`;
        }).join('') : '<span class="muted">没有分组</span>';
        toast('读取到 '+groups.length+' 个分组');
      }catch(e){
        toast(e.message, true);
      }
    }

    async function startRun(){
      try{
        const p = payload();
        const hasSubConfig = !!(p.sub_url || p.sub_email || p.sub_password || p.sub_group_ids || p.sub_group_names);
        if(!p.sub_import && hasSubConfig){
          syncSubImport(true);
          p.sub_import = true;
          toast('检测到已填写 sub 信息，已自动打开“注册成功后立即导入 sub2api”');
        }
        const data = await api('/api/run', p);
        currentJobId = data.job_id;
        toast('任务已启动：'+currentJobId);
        setJobStatus('running', 'Running');
        $('stopBtn').disabled = false;
        pollJob();
        if(pollTimer) clearInterval(pollTimer);
        pollTimer = setInterval(pollJob, 1500);
      }catch(e){
        toast(e.message, true);
      }
    }

    async function stopRun(){
      if(!currentJobId){ toast('还没有运行中的任务', true); return; }
      try{
        $('stopBtn').disabled = true;
        setJobStatus('stopping', 'Stopping');
        await api('/api/job/'+currentJobId+'/stop', {});
        toast('已发送停止请求；当前单条请求返回/超时后停止。');
        pollJob();
      }catch(e){
        $('stopBtn').disabled = false;
        toast(e.message, true);
      }
    }

    async function pollJob(){
      if(!currentJobId) return;
      try{
        const res = await fetch('/api/job/'+currentJobId);
        const body = await res.json();
        if(!body.ok) throw new Error(body.error || '读取任务失败');
        renderJob(body.job);
        if(['finished','failed','stopped'].includes(body.job.status) && pollTimer){
          clearInterval(pollTimer); pollTimer = null;
        }
        if(['finished','failed','stopped'].includes(body.job.status)){
          $('stopBtn').disabled = true;
        }else if(['running','stopping','queued'].includes(body.job.status)){
          $('stopBtn').disabled = false;
        }
      }catch(e){
        toast(e.message, true);
      }
    }

    function renderJob(job){
      setJobStatus(job.status, job.status);
      $('logs').textContent = (job.logs || []).join('\n') || '等待日志...';
      $('logs').scrollTop = $('logs').scrollHeight;

      const s = job.summary || {};
      const total = s.total ?? 0;
      const processed = s.processed ?? 0;
      $('statTotal').textContent = total ? (processed + '/' + total) : '0';
      $('statGenerated').textContent = s.generated ?? 0;
      $('statFailed').textContent = s.failed ?? 0;
      if(s.sub_import){
        const si = s.sub_import;
        const subTotal = si.total || 0;
        const subOk = (si.created || 0) + (si.updated || 0) + (si.skipped || 0);
        const subFailed = si.failed || 0;
        const proxyCleared = si.proxy_cleared || 0;
        $('statSub').textContent = subTotal ? (subOk + '/' + subTotal + (subFailed ? ' F' + subFailed : '') + (proxyCleared ? ' 清代理' + proxyCleared : '')) : '-';
      }else{
        $('statSub').textContent = '-';
      }
      renderFiles(job);
    }

    function renderFiles(job){
      const files = [
        ['summary.json', job.summary_path],
        ['summary.csv', job.csv_path],
        ['sub_import_payload.json', job.payload_path],
        ['errors.jsonl', job.errors_path],
        ['sub_import_result.json', job.sub_import_result_path],
        ['sub_account_tests.json', job.sub_account_tests_path],
      ].filter(x => x[1]);
      if(!files.length){
        $('resultFiles').innerHTML = '暂无结果';
        $('resultFiles').classList.add('muted');
        return;
      }
      $('resultFiles').classList.remove('muted');
      $('resultFiles').innerHTML = files.map(([name,path]) => `
        <div class="result-item">
          <div><b>${escapeHtml(name)}</b><div class="path">${escapeHtml(path)}</div></div>
          <a class="badge" href="/api/job/${currentJobId}/file/${encodeURIComponent(name)}">下载</a>
        </div>`).join('');
    }

    async function openRunDir(){
      if(!currentJobId){ toast('还没有任务结果', true); return; }
      try{
        await api('/api/job/'+currentJobId+'/open-dir', {});
        toast('已打开结果目录');
      }catch(e){
        toast(e.message, true);
      }
    }

    function setJobStatus(status, text){
      const el = $('jobStatus');
      el.className = 'status ' + (status || '');
      el.innerHTML = '<span class="status-dot"></span>' + escapeHtml(text || 'Idle');
    }

    function escapeHtml(s){
      return String(s ?? '').replace(/[&<>"']/g, ch => ({
        '&':'&amp;','<':'&lt;','>':'&gt;','"':'&quot;',"'":'&#39;'
      }[ch]));
    }
  </script>
</body>
</html>
"""


def run_server(host: str, port: int, open_browser: bool = True) -> None:
    server = ThreadingHTTPServer((host, port), CodexAgentWebHandler)
    url = f"http://{host}:{port}/"
    print(f"Codex Agent Web UI started: {url}")
    print("Press Ctrl+C to stop.")
    if open_browser:
        threading.Timer(0.6, lambda: webbrowser.open(url)).start()
    try:
        server.serve_forever()
    except KeyboardInterrupt:
        print("\nStopping...")
    finally:
        server.server_close()


def main() -> None:
    parser = argparse.ArgumentParser(description="Codex Agent Identity 本地 Web 面板")
    parser.add_argument("--host", default=DEFAULT_HOST, help=f"监听地址，默认 {DEFAULT_HOST}")
    parser.add_argument("--port", type=int, default=DEFAULT_PORT, help=f"监听端口，默认 {DEFAULT_PORT}")
    parser.add_argument("--no-open", action="store_true", help="启动后不自动打开浏览器")
    args = parser.parse_args()

    run_server(args.host, args.port, open_browser=not args.no_open)


if __name__ == "__main__":
    main()
