
"""
Codex Agent Identity 批量注册工具
by 久雾

功能：
1. 单个 ChatGPT session JWT 生成一个 Codex CLI auth.json
2. 批量导入多个 accessToken / session.json / auth.json
3. 批量注册并导出多个 Agent Identity auth.json
4. 可选导入到 sub2api 指定分组

依赖：curl_cffi, cryptography
"""

from __future__ import annotations

import argparse
import base64
import csv
import getpass
import hashlib
import json
import os
import re
import sys
import time
import uuid
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any, Callable

from curl_cffi import requests
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey
from cryptography.hazmat.primitives.serialization import (
    Encoding,
    PrivateFormat,
    PublicFormat,
    NoEncryption,
    load_pem_private_key,
)


# ============================================================
#  常量
# ============================================================

AUTHAPI_BASE = "https://auth.openai.com/api/accounts"
CHATGPT_BASE = "https://chatgpt.com"
IMPERSONATE = "chrome"

CHROME_VERSION = "146"
USER_AGENT = (
    f"Mozilla/5.0 (Windows NT 10.0; Win64; x64) "
    f"AppleWebKit/537.36 (KHTML, like Gecko) "
    f"Chrome/{CHROME_VERSION}.0.0.0 Safari/537.36"
)

# Codex CLI agent 版本信息
AGENT_VERSION = "0.138.0-alpha.6"
AGENT_HARNESS_ID = "codex-cli"
RUNNING_LOCATION = "local"

DEFAULT_SUB_CONCURRENCY = 3
DEFAULT_SUB_PRIORITY = 50
JWT_RE = re.compile(r"\beyJ[A-Za-z0-9_-]+\.[A-Za-z0-9_-]+\.[A-Za-z0-9_-]+\b")


# ============================================================
#  日志与安全输出
# ============================================================

_COLORS = {
    "INFO": "\033[36m",
    "WARN": "\033[33m",
    "ERROR": "\033[31m",
    "OK": "\033[32m",
}
_RESET = "\033[0m"
_DIM = "\033[2m"
_BOLD = "\033[1m"


def mask_secret(value: str, prefix: int = 8, suffix: int = 4) -> str:
    if not value:
        return ""
    value = str(value)
    if len(value) <= prefix + suffix:
        return value[:2] + "***"
    return f"{value[:prefix]}...{value[-suffix:]}"


def fingerprint(value: str, length: int = 12) -> str:
    if not value:
        return ""
    return hashlib.sha256(value.encode("utf-8")).hexdigest()[:length]


def redact_text(text: str) -> str:
    if not text:
        return text
    return JWT_RE.sub(lambda m: mask_secret(m.group(0)), str(text))


def _log(step: str, msg: str, level: str = "INFO") -> None:
    ts = time.strftime("%H:%M:%S")
    color = _COLORS.get(level, _COLORS["INFO"])
    lvl = f"{color}{level:<5}{_RESET}"
    print(f"{_DIM}{ts}{_RESET} {lvl} {step:<16} ┃ {redact_text(str(msg))}")


def _banner(title: str) -> None:
    line = "━" * 52
    print(f"\n{_BOLD}{_COLORS['INFO']}┏{line}┓{_RESET}")
    print(f"{_BOLD}{_COLORS['INFO']}┃ {title:^50} ┃{_RESET}")
    print(f"{_BOLD}{_COLORS['INFO']}┗{line}┛{_RESET}\n")


def safe_filename(value: str | None, fallback: str = "item") -> str:
    value = (value or fallback).strip()
    value = re.sub(r"[^A-Za-z0-9._@+-]+", "_", value)
    value = value.strip("._-")
    return (value or fallback)[:80]


def write_json(path: Path, data: Any, *, compact: bool = False) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    with path.open("w", encoding="utf-8") as f:
        if compact:
            json.dump(data, f, ensure_ascii=False, separators=(",", ":"))
        else:
            json.dump(data, f, indent=2, ensure_ascii=False)
            f.write("\n")


def json_compact(data: Any) -> str:
    return json.dumps(data, ensure_ascii=False, separators=(",", ":"))


# ============================================================
#  Ed25519 密钥对生成
# ============================================================


def generate_ed25519_keypair() -> tuple[str, str]:
    """生成 Ed25519 密钥对，返回 (PKCS8 base64 私钥, SSH 格式公钥)。"""
    private_key = Ed25519PrivateKey.generate()

    pkcs8_der = private_key.private_bytes(
        encoding=Encoding.DER,
        format=PrivateFormat.PKCS8,
        encryption_algorithm=NoEncryption(),
    )
    private_key_b64 = base64.b64encode(pkcs8_der).decode()

    public_key = private_key.public_key()
    pub_bytes = public_key.public_bytes(
        encoding=Encoding.Raw,
        format=PublicFormat.Raw,
    )

    ssh_header = b"ssh-ed25519"
    blob = bytearray()
    blob.extend(len(ssh_header).to_bytes(4, "big"))
    blob.extend(ssh_header)
    blob.extend(len(pub_bytes).to_bytes(4, "big"))
    blob.extend(pub_bytes)
    ssh_b64 = base64.b64encode(bytes(blob)).decode()
    public_key_ssh = f"ssh-ed25519 {ssh_b64}"

    return private_key_b64, public_key_ssh


# ============================================================
#  JWT / session 处理
# ============================================================


def decode_jwt_claims(jwt_token: str) -> dict[str, Any]:
    """解码 JWT payload（不验证签名，仅提取 claims）。"""
    parts = jwt_token.split(".")
    if len(parts) != 3:
        raise ValueError("Invalid JWT format")

    payload_b64 = parts[1]
    padding = 4 - len(payload_b64) % 4
    if padding != 4:
        payload_b64 += "=" * padding

    payload_bytes = base64.urlsafe_b64decode(payload_b64)
    return json.loads(payload_bytes)


def get_session_from_cookies(cookies: dict[str, str]) -> dict[str, Any]:
    """使用 chatgpt.com cookies 调用 /api/auth/session 获取 session。"""
    r = requests.get(
        f"{CHATGPT_BASE}/api/auth/session",
        cookies=cookies,
        headers={"user-agent": USER_AGENT},
        impersonate=IMPERSONATE,
        timeout=15,
    )
    r.raise_for_status()
    return r.json()


def get_session_from_access_token(access_token: str) -> dict[str, Any]:
    """已有 JWT accessToken 时，直接解码获取账号字段。"""
    claims = decode_jwt_claims(access_token)
    auth_info = claims.get("https://api.openai.com/auth", {}) or {}
    profile = claims.get("https://api.openai.com/profile", {}) or {}

    account_id = (
        auth_info.get("chatgpt_account_id")
        or auth_info.get("account_id")
        or auth_info.get("accountId")
        or ""
    )
    user_id = (
        auth_info.get("chatgpt_user_id")
        or auth_info.get("user_id")
        or auth_info.get("userId")
        or claims.get("sub")
        or ""
    )
    email = profile.get("email") or claims.get("email") or ""
    plan_type = auth_info.get("chatgpt_plan_type") or auth_info.get("plan_type") or "free"

    return {
        "accessToken": access_token,
        "accountId": account_id,
        "userId": user_id,
        "email": email,
        "planType": plan_type,
    }


def extract_access_token_from_session(data: Any) -> str:
    """从常见 session JSON / 响应包 / 纯文本中提取 accessToken。"""
    if isinstance(data, str):
        text = data.strip().strip('"').strip("'").strip(",")
        match = JWT_RE.search(text)
        return match.group(0) if match else text
    if not isinstance(data, dict):
        return ""

    for key in ("accessToken", "access_token", "access-token", "token"):
        value = data.get(key)
        if isinstance(value, str) and value.strip():
            return value.strip()

    for key in ("data", "session", "auth", "credentials"):
        token = extract_access_token_from_session(data.get(key))
        if token:
            return token

    return ""


# ============================================================
#  Agent / Task 注册
# ============================================================


def register_agent(access_token: str, public_key_ssh: str) -> str:
    """在 auth.openai.com 注册 agent，返回 agent_runtime_id。"""
    r = requests.post(
        f"{AUTHAPI_BASE}/v1/agent/register",
        headers={
            "Content-Type": "application/json",
            "Authorization": f"Bearer {access_token}",
        },
        json={
            "abom": {
                "agent_version": AGENT_VERSION,
                "agent_harness_id": AGENT_HARNESS_ID,
                "running_location": RUNNING_LOCATION,
            },
            "agent_public_key": public_key_ssh,
        },
        impersonate=IMPERSONATE,
        timeout=15,
    )

    if r.status_code != 200:
        raise RuntimeError(f"Agent registration failed: {r.status_code} {redact_text(r.text)}")

    data = r.json()
    agent_runtime_id = data.get("agent_runtime_id")
    if not agent_runtime_id:
        raise RuntimeError(f"No agent_runtime_id in response: {redact_text(str(data))}")

    return agent_runtime_id


def decrypt_agent_task_id(private_key_pkcs8_b64: str, encrypted_task_id: str) -> str:
    """解密 /task/register 返回的 encrypted_task_id，得到 sub2api 需要的明文 task_id。"""
    try:
        from nacl.public import PrivateKey, SealedBox
    except Exception as e:  # pragma: no cover - 仅在缺少 PyNaCl 时触发
        raise RuntimeError("缺少 PyNaCl，无法解密 encrypted_task_id") from e

    pkcs8_der = base64.b64decode(private_key_pkcs8_b64)
    pem = b"-----BEGIN PRIVATE KEY-----\n" + base64.encodebytes(pkcs8_der) + b"-----END PRIVATE KEY-----\n"
    private_key = load_pem_private_key(pem, password=None)
    seed = private_key.private_bytes(
        encoding=Encoding.Raw,
        format=PrivateFormat.Raw,
        encryption_algorithm=NoEncryption(),
    )

    # 与 sub2api/openai_agent_identity.go 保持一致：
    # Ed25519 seed -> SHA512 -> clamp -> X25519 private key -> sealed-box open。
    digest = hashlib.sha512(seed).digest()
    curve_private = bytearray(digest[:32])
    curve_private[0] &= 248
    curve_private[31] &= 127
    curve_private[31] |= 64

    ciphertext = base64.b64decode(encrypted_task_id)
    plaintext = SealedBox(PrivateKey(bytes(curve_private))).decrypt(ciphertext)
    task_id = plaintext.decode("utf-8").strip()
    if not task_id:
        raise RuntimeError("decrypted task_id is empty")
    return task_id


def looks_like_encrypted_task_id(task_id: str) -> bool:
    task_id = (task_id or "").strip()
    if not task_id:
        return False
    if task_id.startswith("task-") or task_id.startswith("task_"):
        return False
    if len(task_id) < 80:
        return False
    try:
        raw = base64.b64decode(task_id, validate=True)
    except Exception:
        return False
    return len(raw) >= 48


def normalize_agent_identity_task_id(auth_json: dict[str, Any], *, verbose: bool = False) -> dict[str, Any]:
    """把旧版本误写入的 encrypted_task_id 修正为明文 task_id，避免 sub 测试 403。"""
    if not isinstance(auth_json, dict):
        return auth_json
    agent_identity = auth_json.get("agent_identity") or auth_json.get("agentIdentity")
    if not isinstance(agent_identity, dict):
        return auth_json

    task_id = str(agent_identity.get("task_id") or agent_identity.get("taskId") or "").strip()
    private_key = str(agent_identity.get("agent_private_key") or agent_identity.get("agentPrivateKey") or "").strip()
    if not task_id or not private_key or not looks_like_encrypted_task_id(task_id):
        return auth_json

    try:
        plain_task_id = decrypt_agent_task_id(private_key, task_id)
        agent_identity["task_id"] = plain_task_id
        if "taskId" in agent_identity:
            agent_identity["taskId"] = plain_task_id
        if verbose:
            _log("Task Fix", f"encrypted_task_id 已转换为 task_id={mask_secret(plain_task_id, 10, 6)}", "OK")
    except Exception as e:
        # 解不开时删除 task_id，让 sub2api 首次请求时自动注册新 task，避免继续导入错误 task_id。
        agent_identity.pop("task_id", None)
        agent_identity.pop("taskId", None)
        if verbose:
            _log("Task Fix", f"encrypted_task_id 解密失败，已移除 task_id，sub 将自动注册新 task: {e}", "WARN")
    return auth_json


def register_task(access_token: str, agent_runtime_id: str, private_key_pkcs8_b64: str) -> str:
    """在 auth.openai.com 注册 task，用于验证密钥对可用性。"""
    pkcs8_der = base64.b64decode(private_key_pkcs8_b64)
    pem = b"-----BEGIN PRIVATE KEY-----\n" + base64.encodebytes(pkcs8_der) + b"-----END PRIVATE KEY-----\n"
    private_key = load_pem_private_key(pem, password=None)

    timestamp = time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime())
    payload = f"{agent_runtime_id}:{timestamp}"
    signature = private_key.sign(payload.encode())
    signature_b64 = base64.b64encode(signature).decode()

    r = requests.post(
        f"{AUTHAPI_BASE}/v1/agent/{agent_runtime_id}/task/register",
        headers={
            "Content-Type": "application/json",
            "Authorization": f"Bearer {access_token}",
        },
        json={"timestamp": timestamp, "signature": signature_b64},
        impersonate=IMPERSONATE,
        timeout=15,
    )

    if r.status_code != 200:
        raise RuntimeError(f"Task registration failed: {r.status_code} {redact_text(r.text)}")

    data = r.json()
    task_id = (data.get("task_id") or data.get("taskId") or "").strip()
    if task_id:
        return task_id

    encrypted_task_id = (data.get("encrypted_task_id") or data.get("encryptedTaskId") or "").strip()
    if encrypted_task_id:
        return decrypt_agent_task_id(private_key_pkcs8_b64, encrypted_task_id)

    return ""




def generate_auth_json(
    agent_runtime_id: str,
    private_key_pkcs8_b64: str,
    account_id: str,
    chatgpt_user_id: str,
    email: str,
    plan_type: str = "free",
    chatgpt_account_is_fedramp: bool = False,
    task_id: str | None = None,
) -> dict[str, Any]:
    """生成 Codex CLI auth.json。"""
    agent_identity: dict[str, Any] = {
        "agent_runtime_id": agent_runtime_id,
        "agent_private_key": private_key_pkcs8_b64,
        "account_id": account_id,
        "chatgpt_user_id": chatgpt_user_id,
        "email": email,
        "plan_type": plan_type,
        "chatgpt_account_is_fedramp": chatgpt_account_is_fedramp,
    }
    if task_id:
        agent_identity["task_id"] = task_id

    return {
        "auth_mode": "agent_identity",
        "agent_identity": agent_identity,
    }


def metadata_from_auth_json(auth_json: dict[str, Any]) -> dict[str, Any]:
    agent_identity = auth_json.get("agent_identity") or auth_json.get("agentIdentity") or auth_json
    if not isinstance(agent_identity, dict):
        agent_identity = {}
    return {
        "email": agent_identity.get("email", ""),
        "account_id": agent_identity.get("account_id") or agent_identity.get("accountId") or "",
        "chatgpt_user_id": agent_identity.get("chatgpt_user_id") or agent_identity.get("chatgptUserId") or "",
        "plan_type": agent_identity.get("plan_type") or agent_identity.get("planType") or "",
        "agent_runtime_id": agent_identity.get("agent_runtime_id") or agent_identity.get("agentRuntimeId") or "",
        "task_id": agent_identity.get("task_id") or agent_identity.get("taskId") or "",
    }


def is_agent_identity_auth(data: Any) -> bool:
    if not isinstance(data, dict):
        return False
    auth_mode = str(data.get("auth_mode") or data.get("authMode") or "").lower()
    return auth_mode == "agent_identity" or isinstance(data.get("agent_identity"), dict)


def build_codex_agent_identity(access_token: str, verify_task: bool = True, verbose: bool = True) -> dict[str, Any]:
    """从 ChatGPT session JWT 创建 Agent Identity auth.json，不直接写文件。"""
    token_fp = fingerprint(access_token)

    if verbose:
        _log("Step 1", f"解码 JWT 获取账号信息 token_fp={token_fp}...")
    session = get_session_from_access_token(access_token)
    account_id = session["accountId"]
    chatgpt_user_id = session["userId"]
    email = session["email"]
    plan_type = session["planType"]

    if not account_id or not chatgpt_user_id:
        raise RuntimeError(f"JWT 缺少必要字段: account_id={account_id}, user_id={chatgpt_user_id}")

    if verbose:
        _log("Step 1", f"account_id={account_id}", "OK")
        _log("Step 1", f"user_id={chatgpt_user_id}", "OK")
        _log("Step 1", f"email={email}", "OK")
        _log("Step 1", f"plan_type={plan_type}", "OK")

    if verbose:
        _log("Step 2", "生成 Ed25519 密钥对...")
    private_key_b64, public_key_ssh = generate_ed25519_keypair()
    if verbose:
        _log("Step 2", f"private_key_fp={fingerprint(private_key_b64)}", "OK")
        _log("Step 2", f"public_key={mask_secret(public_key_ssh, 18, 8)}", "OK")

    if verbose:
        _log("Step 3", "在 auth.openai.com 注册 agent...")
    agent_runtime_id = register_agent(access_token, public_key_ssh)
    if verbose:
        _log("Step 3", f"agent_runtime_id={agent_runtime_id}", "OK")

    task_id = ""
    if verify_task:
        if verbose:
            _log("Step 4", "验证 task 注册...")
        try:
            task_id = register_task(access_token, agent_runtime_id, private_key_b64)
            if verbose:
                _log("Step 4", f"task_id={mask_secret(task_id, 18, 8)}", "OK")
        except Exception as e:
            if verbose:
                _log("Step 4", f"验证失败（不影响 auth.json）: {e}", "WARN")

    if verbose:
        _log("Step 5", "生成 auth.json...")
    return generate_auth_json(
        agent_runtime_id=agent_runtime_id,
        private_key_pkcs8_b64=private_key_b64,
        account_id=account_id,
        chatgpt_user_id=chatgpt_user_id,
        email=email,
        plan_type=plan_type,
        chatgpt_account_is_fedramp=False,
        task_id=task_id or None,
    )


def create_codex_agent_identity(
    access_token: str,
    output_path: str | None = None,
    verify_task: bool = True,
) -> dict[str, Any]:
    """单个流程：从 ChatGPT session JWT 创建 Codex Agent Identity auth.json。"""
    _banner("Codex Agent Identity 注册  ·  by 久雾")
    auth_json = build_codex_agent_identity(access_token, verify_task=verify_task, verbose=True)

    if output_path is None:
        output_path = os.path.join(os.getcwd(), "auth.json")

    output = Path(output_path)
    write_json(output, auth_json)
    _log("Step 5", f"已保存到 {output}", "OK")
    _log("SECURITY", "auth.json 包含 agent_private_key，请勿提交到 git 或公开分享。", "WARN")
    return auth_json


# ============================================================
#  BatchInputLoader：批量输入读取
# ============================================================


@dataclass
class BatchInputItem:
    index: int
    source: str
    kind: str  # access_token / session_json / auth_json
    access_token: str = ""
    auth_json: dict[str, Any] | None = None
    label: str = ""
    token_fingerprint: str = ""


class BatchInputLoader:
    """读取 tokens.txt、sessions.json、目录内多个 session.json/auth.json。"""

    JSON_CONTAINER_KEYS = ("sessions", "items", "accounts", "tokens", "contents")
    SKIP_FILE_NAMES = {
        "summary.json",
        "summary.csv",
        "sub_import_payload.json",
        "sub_import_result.json",
        "sub_account_tests.json",
        "errors.jsonl",
    }

    @classmethod
    def load(cls, path_like: str | os.PathLike[str]) -> list[BatchInputItem]:
        path = Path(path_like).expanduser()
        if not path.exists():
            raise FileNotFoundError(f"输入路径不存在: {path}")

        items: list[BatchInputItem] = []
        if path.is_dir():
            files = sorted(
                p
                for p in path.rglob("*")
                if p.is_file()
                and p.name.lower() not in cls.SKIP_FILE_NAMES
                and p.suffix.lower() in {".json", ".txt", ".list"}
            )
            for file_path in files:
                items.extend(cls._load_file(file_path, allow_empty=True))
        else:
            items.extend(cls._load_file(path, allow_empty=False))

        for i, item in enumerate(items, 1):
            item.index = i
            if item.access_token:
                item.token_fingerprint = fingerprint(item.access_token)

        if not items:
            raise RuntimeError(f"没有从 {path} 读取到 accessToken/session/auth.json")
        return items

    @classmethod
    def _load_file(cls, path: Path, *, allow_empty: bool) -> list[BatchInputItem]:
        suffix = path.suffix.lower()
        try:
            if suffix in {".txt", ".list"}:
                return cls._load_text_tokens(path)
            if suffix == ".json":
                return cls._load_json(path)
            return []
        except Exception:
            if allow_empty:
                return []
            raise

    @classmethod
    def _load_text_tokens(cls, path: Path) -> list[BatchInputItem]:
        items: list[BatchInputItem] = []
        for line_no, raw_line in enumerate(path.read_text(encoding="utf-8-sig").splitlines(), 1):
            line = raw_line.strip()
            if not line or line.startswith("#"):
                continue
            token = extract_access_token_from_session(line)
            if not token:
                continue
            items.append(
                BatchInputItem(
                    index=0,
                    source=f"{path}:{line_no}",
                    kind="access_token",
                    access_token=token,
                    label=f"line_{line_no}",
                )
            )
        return items

    @classmethod
    def _load_json(cls, path: Path) -> list[BatchInputItem]:
        text = path.read_text(encoding="utf-8-sig").strip()
        if not text:
            return []
        data = json.loads(text)
        return cls._items_from_json(data, source=str(path), label_hint=path.stem)

    @classmethod
    def _items_from_json(cls, data: Any, *, source: str, label_hint: str = "") -> list[BatchInputItem]:
        items: list[BatchInputItem] = []

        if isinstance(data, str):
            text = data.strip()
            if not text:
                return items
            if text.startswith("{") or text.startswith("["):
                try:
                    parsed = json.loads(text)
                    return cls._items_from_json(parsed, source=source, label_hint=label_hint)
                except json.JSONDecodeError:
                    pass
            token = extract_access_token_from_session(text)
            if token:
                items.append(
                    BatchInputItem(
                        index=0,
                        source=source,
                        kind="access_token",
                        access_token=token,
                        label=label_hint,
                    )
                )
            return items

        if isinstance(data, list):
            for offset, value in enumerate(data, 1):
                items.extend(
                    cls._items_from_json(
                        value,
                        source=f"{source}#{offset}",
                        label_hint=f"{label_hint}_{offset}" if label_hint else str(offset),
                    )
                )
            return items

        if not isinstance(data, dict):
            return items

        if is_agent_identity_auth(data):
            meta = metadata_from_auth_json(data)
            label = meta.get("email") or meta.get("chatgpt_user_id") or meta.get("account_id") or label_hint
            items.append(
                BatchInputItem(
                    index=0,
                    source=source,
                    kind="auth_json",
                    auth_json=data,
                    label=label,
                )
            )
            return items

        # sub 导入 payload: {"contents": ["{...auth...}", "eyJ..."]}
        if isinstance(data.get("contents"), list):
            for offset, value in enumerate(data["contents"], 1):
                items.extend(
                    cls._items_from_json(
                        value,
                        source=f"{source}#contents[{offset}]",
                        label_hint=f"{label_hint}_{offset}" if label_hint else str(offset),
                    )
                )
            return items

        token = extract_access_token_from_session(data)
        if token:
            user = data.get("user")
            label = data.get("email") or (user.get("email") if isinstance(user, dict) else "") or label_hint
            items.append(
                BatchInputItem(
                    index=0,
                    source=source,
                    kind="session_json",
                    access_token=token,
                    label=label,
                )
            )
            return items

        for key in cls.JSON_CONTAINER_KEYS:
            value = data.get(key)
            if isinstance(value, list):
                for offset, child in enumerate(value, 1):
                    items.extend(
                        cls._items_from_json(
                            child,
                            source=f"{source}#{key}[{offset}]",
                            label_hint=f"{label_hint}_{offset}" if label_hint else str(offset),
                        )
                    )
                if items:
                    return items

        return items


# ============================================================
#  BatchProcessor：批量生成/导出/汇总
# ============================================================


@dataclass
class BatchRun:
    run_dir: Path
    auth_dir: Path
    input_total: int = 0
    results: list[dict[str, Any]] = field(default_factory=list)
    auth_jsons: list[dict[str, Any]] = field(default_factory=list)
    auth_contents: list[str] = field(default_factory=list)
    errors_path: Path | None = None
    payload_path: Path | None = None
    summary_path: Path | None = None
    csv_path: Path | None = None
    sub_import_result_path: Path | None = None
    sub_account_tests_path: Path | None = None
    sub_import_result: dict[str, Any] | None = None
    sub_account_tests: list[dict[str, Any]] = field(default_factory=list)

    def write_sub_payload(
        self,
        *,
        group_ids: list[int] | None = None,
        concurrency: int = DEFAULT_SUB_CONCURRENCY,
        priority: int = DEFAULT_SUB_PRIORITY,
        update_existing: bool = True,
        skip_default_group_bind: bool = True,
        confirm_mixed_channel_risk: bool | None = None,
    ) -> Path:
        payload: dict[str, Any] = {
            "contents": self.auth_contents,
            "group_ids": group_ids or [],
            "concurrency": concurrency,
            "priority": priority,
            "update_existing": update_existing,
            "skip_default_group_bind": skip_default_group_bind,
        }
        if confirm_mixed_channel_risk is not None:
            payload["confirm_mixed_channel_risk"] = confirm_mixed_channel_risk
        self.payload_path = self.run_dir / "sub_import_payload.json"
        write_json(self.payload_path, payload)
        return self.payload_path

    def write_summary(self) -> tuple[Path, Path]:
        total = self.input_total or len(self.results)
        processed = len(self.results)
        generated = sum(1 for r in self.results if r.get("status") == "success" and r.get("kind") != "auth_json")
        copied = sum(1 for r in self.results if r.get("status") == "success" and r.get("kind") == "auth_json")
        failed = sum(1 for r in self.results if r.get("status") != "success")
        sub_import_summary = None
        if self.sub_import_result:
            proxy_clear_rows = self.sub_import_result.get("proxy_clear") or []
            sub_import_summary = {
                "total": self.sub_import_result.get("total", 0),
                "created": self.sub_import_result.get("created", 0),
                "updated": self.sub_import_result.get("updated", 0),
                "skipped": self.sub_import_result.get("skipped", 0),
                "failed": self.sub_import_result.get("failed", 0),
                "proxy_cleared": sum(1 for x in proxy_clear_rows if isinstance(x, dict) and x.get("success") is True),
                "proxy_clear_failed": sum(1 for x in proxy_clear_rows if isinstance(x, dict) and x.get("success") is not True),
            }

        account_test_summary = None
        if self.sub_account_tests:
            account_test_summary = {
                "total": len(self.sub_account_tests),
                "success": sum(1 for x in self.sub_account_tests if x.get("success") is True),
                "failed": sum(1 for x in self.sub_account_tests if x.get("success") is not True),
            }

        summary = {
            "total": total,
            "processed": processed,
            "generated": generated,
            "copied_auth_json": copied,
            "failed": failed,
            "stopped_remaining": max(total - processed, 0),
            "ready_for_import": len(self.auth_contents),
            "run_dir": str(self.run_dir),
            "auth_dir": str(self.auth_dir),
            "sub_import_payload": str(self.payload_path) if self.payload_path else "",
            "sub_import": sub_import_summary,
            "sub_account_tests": account_test_summary,
            "items": self.results,
        }
        self.summary_path = self.run_dir / "summary.json"
        write_json(self.summary_path, summary)

        self.csv_path = self.run_dir / "summary.csv"
        fieldnames = [
            "index",
            "source",
            "kind",
            "status",
            "email",
            "account_id",
            "chatgpt_user_id",
            "plan_type",
            "agent_runtime_id",
            "task_id",
            "token_fingerprint",
            "output_file",
            "error",
        ]
        with self.csv_path.open("w", encoding="utf-8-sig", newline="") as f:
            writer = csv.DictWriter(f, fieldnames=fieldnames)
            writer.writeheader()
            for row in self.results:
                writer.writerow({key: row.get(key, "") for key in fieldnames})

        return self.summary_path, self.csv_path


class BatchProcessor:
    """串行处理批量 AT/session，保存 auth.json 与 summary。"""

    def __init__(self, out_dir: str | os.PathLike[str], *, verify_task: bool = True):
        self.out_dir = Path(out_dir).expanduser().resolve()
        self.verify_task = verify_task

    def create_run_dir(self) -> tuple[Path, Path]:
        stamp = time.strftime("%Y%m%d-%H%M%S")
        run_dir = self.out_dir / stamp
        suffix = 1
        while run_dir.exists():
            suffix += 1
            run_dir = self.out_dir / f"{stamp}-{suffix}"
        auth_dir = run_dir / "auth"
        auth_dir.mkdir(parents=True, exist_ok=True)
        return run_dir, auth_dir

    def process(
        self,
        items: list[BatchInputItem],
        *,
        progress_callback: Callable[[BatchRun], None] | None = None,
        cancel_check: Callable[[], bool] | None = None,
    ) -> BatchRun:
        run_dir, auth_dir = self.create_run_dir()
        errors_path = run_dir / "errors.jsonl"
        batch_run = BatchRun(run_dir=run_dir, auth_dir=auth_dir, input_total=len(items), errors_path=errors_path)

        _banner("Codex Agent Identity 批量注册")
        _log("Batch", f"输入 {len(items)} 条，输出目录 {run_dir}")

        for item in items:
            if cancel_check and cancel_check():
                _log("Batch", f"收到停止信号，已停止处理后续输入，剩余 {len(items) - len(batch_run.results)} 条未处理。", "WARN")
                break

            result: dict[str, Any] = {
                "index": item.index,
                "source": item.source,
                "kind": item.kind,
                "status": "pending",
                "email": "",
                "account_id": "",
                "chatgpt_user_id": "",
                "plan_type": "",
                "agent_runtime_id": "",
                "task_id": "",
                "token_fingerprint": item.token_fingerprint,
                "output_file": "",
                "error": "",
            }
            try:
                _log("Batch", f"[{item.index}/{len(items)}] 处理 {item.kind} source={item.source}")

                if item.kind == "auth_json":
                    if not item.auth_json:
                        raise RuntimeError("auth_json 内容为空")
                    auth_json = normalize_agent_identity_task_id(item.auth_json, verbose=True)
                    meta = metadata_from_auth_json(auth_json)
                    _log("Batch", f"[{item.index}] 复用已有 auth_json email={meta.get('email', '')}", "OK")
                else:
                    if not item.access_token:
                        raise RuntimeError("缺少 accessToken")
                    auth_json = build_codex_agent_identity(
                        item.access_token,
                        verify_task=self.verify_task,
                        verbose=False,
                    )
                    meta = metadata_from_auth_json(auth_json)
                    _log(
                        "Batch",
                        f"[{item.index}] 注册成功 email={meta.get('email', '')} runtime={meta.get('agent_runtime_id', '')}",
                        "OK",
                    )

                label = item.label or meta.get("email") or meta.get("chatgpt_user_id") or meta.get("account_id")
                filename = f"{item.index:03d}_{safe_filename(label, f'item_{item.index}')}_auth.json"
                output_path = auth_dir / filename
                write_json(output_path, auth_json)

                result.update(meta)
                result.update({"status": "success", "output_file": str(output_path)})
                batch_run.auth_jsons.append(auth_json)
                batch_run.auth_contents.append(json_compact(auth_json))

            except Exception as e:
                err = redact_text(str(e))
                result.update({"status": "failed", "error": err})
                errors_path.parent.mkdir(parents=True, exist_ok=True)
                with errors_path.open("a", encoding="utf-8") as f:
                    f.write(json_compact(result) + "\n")
                _log("Batch", f"[{item.index}] 失败: {err}", "ERROR")

            batch_run.results.append(result)
            if progress_callback:
                progress_callback(batch_run)

        batch_run.write_sub_payload()
        batch_run.write_summary()
        if progress_callback:
            progress_callback(batch_run)
        _log(
            "Batch",
            f"完成 generated={sum(1 for r in batch_run.results if r.get('status') == 'success' and r.get('kind') != 'auth_json')} "
            f"copied={sum(1 for r in batch_run.results if r.get('status') == 'success' and r.get('kind') == 'auth_json')} "
            f"failed={sum(1 for r in batch_run.results if r.get('status') != 'success')}",
            "OK",
        )
        return batch_run


# ============================================================
#  Sub2APIClient：登录/测试/分组解析/导入/账号测试
# ============================================================


class Sub2APIClient:
    def __init__(self, base_url: str, email: str, *, timeout: int = 30):
        self.base_url = base_url.rstrip("/")
        self.email = email
        self.timeout = timeout
        self.access_token = ""
        self.token_type = "Bearer"

    def _url(self, path: str) -> str:
        path = "/" + path.lstrip("/")
        base = self.base_url.rstrip("/")
        if base.endswith("/api/v1") and path.startswith("/api/v1/"):
            path = path[len("/api/v1") :]
        return base + path

    def _headers(self, *, auth: bool = True, extra: dict[str, str] | None = None) -> dict[str, str]:
        headers = {
            "Accept": "application/json",
            "Content-Type": "application/json",
            "User-Agent": USER_AGENT,
        }
        if auth and self.access_token:
            headers["Authorization"] = f"{self.token_type or 'Bearer'} {self.access_token}"
        if extra:
            headers.update(extra)
        return headers

    def _decode_response(self, response: Any) -> Any:
        text = response.text or ""
        try:
            body = response.json()
        except Exception:
            body = None

        if response.status_code < 200 or response.status_code >= 300:
            message = text[:500]
            if isinstance(body, dict):
                message = body.get("message") or body.get("error") or message
            raise RuntimeError(f"HTTP {response.status_code}: {redact_text(message)}")

        if isinstance(body, dict) and "code" in body and "message" in body:
            if body.get("code") not in (0, None):
                raise RuntimeError(f"Sub API error: {body.get('message')}")
            return body.get("data")
        return body

    def _request(self, method: str, path: str, *, auth: bool = True, **kwargs: Any) -> Any:
        response = requests.request(
            method,
            self._url(path),
            headers=self._headers(auth=auth, extra=kwargs.pop("headers", None)),
            timeout=kwargs.pop("timeout", self.timeout),
            **kwargs,
        )
        return self._decode_response(response)

    def login(self, password: str | None = None) -> str:
        if password is None:
            password = getpass.getpass("Sub password: ")

        data = self._request(
            "POST",
            "/api/v1/auth/login",
            auth=False,
            json={"email": self.email, "password": password},
        )
        if isinstance(data, dict) and data.get("requires_2fa"):
            temp_token = data.get("temp_token") or ""
            code = input("Sub 2FA code: ").strip()
            data = self._request(
                "POST",
                "/api/v1/auth/login/2fa",
                auth=False,
                json={"temp_token": temp_token, "totp_code": code},
            )

        if not isinstance(data, dict):
            raise RuntimeError("登录响应格式异常")
        access_token = data.get("access_token") or data.get("accessToken") or ""
        if not access_token:
            raise RuntimeError(f"登录响应缺少 access_token: {data}")
        self.access_token = access_token
        self.token_type = data.get("token_type") or data.get("tokenType") or "Bearer"
        _log("Sub", f"登录成功 token_fp={fingerprint(access_token)}", "OK")
        return access_token

    def test_connection(self, password: str | None = None) -> dict[str, Any]:
        steps: list[dict[str, Any]] = []

        try:
            response = requests.get(self.base_url, headers={"User-Agent": USER_AGENT}, timeout=self.timeout)
            steps.append({"step": "reach", "ok": True, "status_code": response.status_code})
            _log("Sub Test", f"地址可达 status={response.status_code}", "OK")
        except Exception as e:
            steps.append({"step": "reach", "ok": False, "error": redact_text(str(e))})
            _log("Sub Test", f"地址连通测试失败: {e}", "ERROR")
            return {"ok": False, "steps": steps}

        try:
            self.login(password)
            steps.append({"step": "login", "ok": True})
        except Exception as e:
            steps.append({"step": "login", "ok": False, "error": redact_text(str(e))})
            _log("Sub Test", f"登录失败: {e}", "ERROR")
            return {"ok": False, "steps": steps}

        try:
            groups = self.list_groups()
            steps.append({"step": "groups", "ok": True, "count": len(groups)})
            _log("Sub Test", f"groups/all 成功，分组数={len(groups)}", "OK")
        except Exception as e:
            steps.append({"step": "groups", "ok": False, "error": redact_text(str(e))})
            _log("Sub Test", f"groups/all 失败: {e}", "ERROR")
            return {"ok": False, "steps": steps}

        return {"ok": True, "steps": steps}

    def list_groups(self) -> list[dict[str, Any]]:
        data = self._request("GET", "/api/v1/admin/groups/all")
        if data is None:
            return []
        if isinstance(data, list):
            return [x for x in data if isinstance(x, dict)]
        if isinstance(data, dict) and isinstance(data.get("items"), list):
            return [x for x in data["items"] if isinstance(x, dict)]
        raise RuntimeError(f"groups/all 响应格式异常: {data}")

    def resolve_group_ids(self, group_ids: list[int] | None = None, group_names: list[str] | None = None) -> list[int]:
        resolved: list[int] = []
        for group_id in group_ids or []:
            if group_id not in resolved:
                resolved.append(group_id)

        names = [name.strip() for name in (group_names or []) if name and name.strip()]
        if names:
            groups = self.list_groups()
            by_name: dict[str, dict[str, Any]] = {}
            for group in groups:
                name = str(group.get("name") or group.get("display_name") or "").strip()
                if name:
                    by_name[name.lower()] = group

            missing: list[str] = []
            for name in names:
                group = by_name.get(name.lower())
                if not group:
                    missing.append(name)
                    continue
                raw_id = group.get("id") or group.get("ID")
                if raw_id is None:
                    missing.append(name)
                    continue
                group_id = int(raw_id)
                if group_id not in resolved:
                    resolved.append(group_id)

            if missing:
                available = [
                    f"{g.get('id') or g.get('ID')}:{g.get('name') or g.get('display_name')}"
                    for g in groups
                    if g.get("id") is not None or g.get("ID") is not None
                ]
                raise RuntimeError(
                    "分组名未找到: "
                    + ", ".join(missing)
                    + "；可用分组: "
                    + ", ".join(available)
                )

        return resolved

    def import_codex_sessions(
        self,
        contents: list[str],
        *,
        group_ids: list[int] | None = None,
        concurrency: int = DEFAULT_SUB_CONCURRENCY,
        priority: int = DEFAULT_SUB_PRIORITY,
        update_existing: bool = True,
        skip_default_group_bind: bool = True,
        confirm_mixed_channel_risk: bool | None = None,
    ) -> dict[str, Any]:
        payload: dict[str, Any] = {
            "contents": contents,
            "group_ids": group_ids or [],
            "concurrency": concurrency,
            "priority": priority,
            "update_existing": update_existing,
            "skip_default_group_bind": skip_default_group_bind,
        }
        if confirm_mixed_channel_risk is not None:
            payload["confirm_mixed_channel_risk"] = confirm_mixed_channel_risk

        data = self._request(
            "POST",
            "/api/v1/admin/accounts/import/codex-session",
            json=payload,
            headers={"Idempotency-Key": f"codex-agent-batch-{uuid.uuid4()}"},
            timeout=120,
        )
        if not isinstance(data, dict):
            raise RuntimeError(f"导入响应格式异常: {data}")
        _log(
            "Sub Import",
            f"total={data.get('total', 0)} created={data.get('created', 0)} updated={data.get('updated', 0)} "
            f"skipped={data.get('skipped', 0)} failed={data.get('failed', 0)}",
            "OK" if int(data.get("failed", 0) or 0) == 0 else "WARN",
        )
        return data

    @staticmethod
    def imported_account_ids(import_result: dict[str, Any]) -> list[int]:
        """从 sub 导入响应里提取账号 ID，自动去重。"""
        account_ids: list[int] = []
        for item in import_result.get("items", []) if isinstance(import_result, dict) else []:
            if not isinstance(item, dict):
                continue
            raw_id = item.get("account_id") or item.get("accountId")
            if raw_id is None:
                continue
            try:
                account_id = int(raw_id)
            except Exception:
                continue
            if account_id > 0 and account_id not in account_ids:
                account_ids.append(account_id)
        return account_ids

    def clear_account_proxy(self, account_id: int) -> dict[str, Any]:
        """清除 sub 账号代理。sub 的更新接口约定 proxy_id=0 表示清除代理。"""
        data = self._request(
            "PUT",
            f"/api/v1/admin/accounts/{int(account_id)}",
            json={"proxy_id": 0},
            headers={"Idempotency-Key": f"codex-agent-clear-proxy-{uuid.uuid4()}"},
            timeout=60,
        )
        if isinstance(data, dict):
            return data
        return {"account_id": int(account_id), "result": data}

    def clear_imported_account_proxies(self, import_result: dict[str, Any]) -> list[dict[str, Any]]:
        """导入后立即清除本次 created/updated 账号上的代理，避免复用旧账号时继承旧代理。"""
        results: list[dict[str, Any]] = []
        for account_id in self.imported_account_ids(import_result):
            try:
                data = self.clear_account_proxy(account_id)
                row = {"account_id": account_id, "success": True}
                if isinstance(data, dict):
                    proxy_id = data.get("proxy_id") or data.get("proxyId")
                    row["proxy_id"] = proxy_id
                results.append(row)
                _log("Sub Proxy", f"account_id={account_id} 已清除代理", "OK")
            except Exception as e:
                row = {"account_id": account_id, "success": False, "message": redact_text(str(e))}
                results.append(row)
                _log("Sub Proxy", f"account_id={account_id} 清除代理失败: {e}", "WARN")
        return results

    def test_imported_accounts(self, import_result: dict[str, Any]) -> list[dict[str, Any]]:
        account_ids = self.imported_account_ids(import_result)

        results: list[dict[str, Any]] = []
        for account_id in account_ids:
            try:
                data = self._request("POST", f"/api/v1/admin/accounts/{account_id}/test", timeout=120)
                if isinstance(data, dict):
                    row = {"account_id": account_id, **data}
                else:
                    row = {"account_id": account_id, "success": True, "message": str(data)}
                results.append(row)
                _log(
                    "Sub TestAcct",
                    f"account_id={account_id} success={row.get('success')} {row.get('message', '')}",
                    "OK" if row.get("success") else "WARN",
                )
            except Exception as e:
                row = {"account_id": account_id, "success": False, "message": redact_text(str(e))}
                results.append(row)
                _log("Sub TestAcct", f"account_id={account_id} 失败: {e}", "ERROR")
        return results


# ============================================================
#  CLI
# ============================================================


def parse_group_ids(values: list[str] | None) -> list[int]:
    ids: list[int] = []
    for value in values or []:
        for part in str(value).replace(";", ",").split(","):
            part = part.strip()
            if not part:
                continue
            group_id = int(part)
            if group_id not in ids:
                ids.append(group_id)
    return ids


def resolve_sub_password(args: argparse.Namespace) -> str | None:
    if getattr(args, "sub_password", None):
        return args.sub_password
    env_password = os.environ.get("SUB2API_PASSWORD")
    if env_password:
        return env_password
    return None


def make_sub_client(args: argparse.Namespace) -> Sub2APIClient:
    if not args.sub_url:
        raise SystemExit("请提供 --sub-url")
    if not args.sub_email:
        raise SystemExit("请提供 --sub-email")
    return Sub2APIClient(args.sub_url, args.sub_email, timeout=args.sub_timeout)


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(description="Codex Agent Identity 自动/批量注册")

    # 兼容原单个模式
    parser.add_argument("--token", type=str, help="ChatGPT session JWT (accessToken)")
    parser.add_argument("--file", type=str, help="包含 accessToken 的单个 JSON 文件路径")
    parser.add_argument("--output", "-o", type=str, default=None, help="单个模式输出路径 (默认: 桌面\\auth.json)")
    parser.add_argument("--no-verify", action="store_true", help="跳过 task 注册验证")

    # 批量模式
    parser.add_argument("--batch", type=str, help="批量输入：tokens.txt / sessions.json / 包含 session.json 或 auth.json 的目录")
    parser.add_argument("--out-dir", type=str, default="results", help="批量输出根目录 (默认: .\\results)")

    # sub2api
    parser.add_argument("--sub-url", type=str, default=None, help="sub2api 地址，例如 https://sub.example.com")
    parser.add_argument("--sub-email", type=str, default=None, help="sub2api 管理员邮箱")
    parser.add_argument("--sub-password", type=str, default=None, help="sub2api 管理员密码；建议留空并运行时隐藏输入")
    parser.add_argument("--sub-test", action="store_true", help="测试 sub 连接：地址可达、登录、groups/all")
    parser.add_argument("--sub-import", action="store_true", help="生成后导入到 sub2api")
    parser.add_argument("--sub-group-id", action="append", help="导入分组 ID，可重复传入或逗号分隔，例如 --sub-group-id 1,2")
    parser.add_argument("--sub-group-name", action="append", help="导入分组名，可重复传入")
    parser.add_argument("--sub-concurrency", type=int, default=DEFAULT_SUB_CONCURRENCY, help="导入账号并发配置 (默认: 3)")
    parser.add_argument("--sub-priority", type=int, default=DEFAULT_SUB_PRIORITY, help="导入账号优先级 (默认: 50)")
    parser.add_argument("--no-sub-update-existing", action="store_true", help="导入时不更新已有账号")
    parser.add_argument("--sub-bind-default-group", action="store_true", help="导入时允许绑定默认分组；默认跳过默认分组绑定")
    parser.add_argument("--sub-confirm-mixed-channel-risk", action="store_true", help="传给 sub 的 confirm_mixed_channel_risk=true")
    parser.add_argument("--sub-test-accounts", action="store_true", help="导入后逐个 POST /admin/accounts/:id/test")
    parser.add_argument("--sub-timeout", type=int, default=30, help="sub 请求超时秒数 (默认: 30)")

    return parser


def load_single_access_token(args: argparse.Namespace) -> str:
    access_token = ""
    if args.token:
        access_token = args.token.strip()
    elif args.file:
        path = Path(args.file).expanduser()
        data = json.loads(path.read_text(encoding="utf-8-sig"))
        access_token = extract_access_token_from_session(data)
    else:
        print("请输入 ChatGPT session JWT (accessToken)：")
        print("（可从 chatgpt.com /api/auth/session 获取）")
        access_token = input("> ").strip()

    if not access_token:
        raise SystemExit("错误：未提供 access_token")
    return access_token


def run_sub_test(args: argparse.Namespace, client: Sub2APIClient | None = None) -> Sub2APIClient:
    client = client or make_sub_client(args)
    password = resolve_sub_password(args)
    result = client.test_connection(password)
    if not result.get("ok"):
        raise SystemExit(2)
    _log("Sub Test", "连接可用", "OK")
    return client


def run_batch(args: argparse.Namespace) -> BatchRun:
    items = BatchInputLoader.load(args.batch)
    batch = BatchProcessor(args.out_dir, verify_task=not args.no_verify)
    batch_run = batch.process(items)

    if args.sub_import:
        if not batch_run.auth_contents:
            raise SystemExit(f"没有可导入到 sub 的 auth.json 内容，请查看 {batch_run.summary_path} 和 {batch_run.errors_path}")

        client = make_sub_client(args)
        if args.sub_test:
            client = run_sub_test(args, client)
        else:
            client.login(resolve_sub_password(args))

        group_ids = client.resolve_group_ids(parse_group_ids(args.sub_group_id), args.sub_group_name or [])
        batch_run.write_sub_payload(
            group_ids=group_ids,
            concurrency=args.sub_concurrency,
            priority=args.sub_priority,
            update_existing=not args.no_sub_update_existing,
            skip_default_group_bind=not args.sub_bind_default_group,
            confirm_mixed_channel_risk=True if args.sub_confirm_mixed_channel_risk else None,
        )
        _log("Sub Import", f"准备导入 {len(batch_run.auth_contents)} 条，group_ids={group_ids}")
        import_result = client.import_codex_sessions(
            batch_run.auth_contents,
            group_ids=group_ids,
            concurrency=args.sub_concurrency,
            priority=args.sub_priority,
            update_existing=not args.no_sub_update_existing,
            skip_default_group_bind=not args.sub_bind_default_group,
            confirm_mixed_channel_risk=True if args.sub_confirm_mixed_channel_risk else None,
        )
        import_result["proxy_clear"] = client.clear_imported_account_proxies(import_result)
        batch_run.sub_import_result = import_result
        batch_run.sub_import_result_path = batch_run.run_dir / "sub_import_result.json"
        write_json(batch_run.sub_import_result_path, import_result)

        if args.sub_test_accounts:
            tests = client.test_imported_accounts(import_result)
            batch_run.sub_account_tests = tests
            batch_run.sub_account_tests_path = batch_run.run_dir / "sub_account_tests.json"
            write_json(batch_run.sub_account_tests_path, tests)

        batch_run.write_summary()

    _log("Output", f"auth_dir={batch_run.auth_dir}", "OK")
    _log("Output", f"summary={batch_run.summary_path}", "OK")
    _log("Output", f"csv={batch_run.csv_path}", "OK")
    _log("SECURITY", "输出 auth/*.json 包含 agent_private_key，请勿提交到 git 或公开分享。", "WARN")
    return batch_run


def run_single(args: argparse.Namespace) -> dict[str, Any]:
    access_token = load_single_access_token(args)
    output_path = args.output or os.path.join(os.path.expanduser("~"), "Desktop", "auth.json")
    auth_json = create_codex_agent_identity(
        access_token=access_token,
        output_path=output_path,
        verify_task=not args.no_verify,
    )

    if args.sub_import:
        client = make_sub_client(args)
        if args.sub_test:
            client = run_sub_test(args, client)
        else:
            client.login(resolve_sub_password(args))
        group_ids = client.resolve_group_ids(parse_group_ids(args.sub_group_id), args.sub_group_name or [])
        result = client.import_codex_sessions(
            [json_compact(auth_json)],
            group_ids=group_ids,
            concurrency=args.sub_concurrency,
            priority=args.sub_priority,
            update_existing=not args.no_sub_update_existing,
            skip_default_group_bind=not args.sub_bind_default_group,
            confirm_mixed_channel_risk=True if args.sub_confirm_mixed_channel_risk else None,
        )
        result["proxy_clear"] = client.clear_imported_account_proxies(result)
        import_result_path = Path(output_path).with_name(Path(output_path).stem + "_sub_import_result.json")
        write_json(import_result_path, result)
        _log("Sub Import", f"导入结果已保存 {import_result_path}", "OK")
        if args.sub_test_accounts:
            tests = client.test_imported_accounts(result)
            test_path = Path(output_path).with_name(Path(output_path).stem + "_sub_account_tests.json")
            write_json(test_path, tests)
            _log("Sub TestAcct", f"测试结果已保存 {test_path}", "OK")

    return auth_json


def main() -> None:
    parser = build_parser()
    args = parser.parse_args()

    if args.sub_test and not args.batch and not args.sub_import and not args.token and not args.file:
        run_sub_test(args)
        return

    if args.batch:
        run_batch(args)
        return

    run_single(args)


if __name__ == "__main__":
    main()
