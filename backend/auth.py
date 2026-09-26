"""用户、会话与权限。

- 口令: PBKDF2-HMAC-SHA256, 12 万轮, 每用户随机盐; 文件里只存盐+摘要。
- 会话: 登录发 token(secrets.token_urlsafe), 存 users.json 的 sessions
  段, 滑动过期; REST 走 X-Auth-Token 头, WebSocket 走 ?token= 查询参数。
- 用户名大小写不敏感: 一律以 canonical(去空格+小写)形式作为内部键,
  注册/登录/ACL/owner 比较都走 canonical, 展示昵称用 display_name。
- 全局角色: admin / user。
- 白板级 ACL(存于各白板 meta.json):
      owner > editor > commenter > viewer
  判定优先级(全系统唯一入口 board_role):
      系统管理员 > 白板所有者(owner) > 成员授权(acl) > 邀请链接默认角色
  owner 记录在 meta.owner; 其他人在 meta.acl 里; public_role 只对
  「既不是 owner 也不在 acl 里的已登录用户」生效, 不会覆盖既有成员授权。
- 能力判定统一走 can_view / can_comment / can_edit / can_manage;
  所有权限判断都在服务端(WS 操作接入与 REST 依赖注入)强制执行,
  前端仅做展示层隐藏。
"""
from __future__ import annotations

import hashlib
import hmac
import re
import secrets
import threading
import time
from typing import Any, Dict, List, Optional, Tuple

from fastapi import Depends, HTTPException, Request

from . import config
from .storage import read_json, write_json_atomic

PBKDF2_ROUNDS = 120_000
USERNAME_RE = re.compile(r"^[a-zA-Z0-9_一-鿿]{2,24}$")

ROLE_ORDER = {"viewer": 1, "commenter": 2, "editor": 3, "owner": 4}
VALID_ROLES = set(ROLE_ORDER.keys())

_store_lock = threading.RLock()


def canonical_username(name: Optional[str]) -> str:
    """用户名内部键: 去首尾空格 + 小写。大小写不敏感的唯一归一化入口。"""
    return (name or "").strip().lower()


def normalize_acl(acl: Any) -> Dict[str, str]:
    """把外部传入/磁盘上的 acl 归一成 {canonical_username: role}。

    - 键一律 canonical(小写), 容忍历史上用混合大小写写入的条目;
    - 非法角色/空键丢弃; owner 不应出现在 acl(由调用方另行剔除)。
    """
    out: Dict[str, str] = {}
    if isinstance(acl, dict):
        for name, role in acl.items():
            key = canonical_username(name)
            if key and role in VALID_ROLES:
                out[key] = role
    return out


# ---------------------------------------------------------------- 底层存取
def _load_store() -> Dict[str, Any]:
    with _store_lock:
        data = read_json(config.USERS_FILE, default=None)
        if not isinstance(data, dict):
            data = {"users": {}, "sessions": {}}
        data.setdefault("users", {})
        data.setdefault("sessions", {})
        return data


def _save_store(data: Dict[str, Any]) -> None:
    with _store_lock:
        write_json_atomic(config.USERS_FILE, data)


def _hash_password(password: str, salt: bytes) -> str:
    dk = hashlib.pbkdf2_hmac("sha256", password.encode("utf-8"), salt, PBKDF2_ROUNDS)
    return dk.hex()


PALETTE = ["#5b8ff9", "#61c0a8", "#f0884d", "#d4709c", "#9270ca",
           "#5ad8a6", "#f6bd16", "#e8684a", "#6dc8ec", "#ff9d4d"]


def _pick_color(index: int) -> str:
    return PALETTE[index % len(PALETTE)]


# ---------------------------------------------------------------- 用户管理
def register_user(username: str, password: str, display_name: Optional[str] = None) -> Dict[str, Any]:
    username = canonical_username(username)
    if not USERNAME_RE.match(username):
        raise ValueError("用户名需为 2-24 位中英文/数字/下划线")
    if len(password or "") < 4:
        raise ValueError("密码至少 4 位")
    with _store_lock:
        data = _load_store()
        if username in data["users"]:
            raise ValueError("用户名已存在")
        salt = secrets.token_bytes(16)
        user = {
            "username": username,
            "display_name": (display_name or username)[:40],
            "salt": salt.hex(),
            "hash": _hash_password(password, salt),
            "role": "admin" if not data["users"] else "user",   # 首个注册用户是管理员
            "disabled": False,
            "color": _pick_color(len(data["users"])),
            "created_at": int(time.time() * 1000),
            "last_login": 0,
        }
        data["users"][username] = user
        _save_store(data)
        return public_user(user)


def public_user(user: Dict[str, Any]) -> Dict[str, Any]:
    return {
        "username": user.get("username"),
        "display_name": user.get("display_name") or user.get("username"),
        "role": user.get("role", "user"),
        "color": user.get("color", "#5b8ff9"),
        "disabled": bool(user.get("disabled")),
        "created_at": user.get("created_at"),
        "last_login": user.get("last_login"),
    }


def verify_login(username: str, password: str) -> Tuple[Dict[str, Any], str]:
    """校验口令, 返回 (public_user, token)。"""
    with _store_lock:
        data = _load_store()
        user = data["users"].get(canonical_username(username))
        if user is None:
            raise PermissionError("用户名或密码错误")
        if user.get("disabled"):
            raise PermissionError("账号已停用")
        salt = bytes.fromhex(user.get("salt", ""))
        if not hmac.compare_digest(_hash_password(password or "", salt), user.get("hash", "")):
            raise PermissionError("用户名或密码错误")
        # 清理过期会话 + 发新 token
        now = time.time()
        sessions = data["sessions"]
        for tok in [t for t, s in sessions.items() if s.get("expires", 0) < now]:
            sessions.pop(tok, None)
        token = secrets.token_urlsafe(24)
        sessions[token] = {
            "user": user["username"],
            "created": int(now * 1000),
            "expires": now + config.SESSION_TTL_SECS,
        }
        user["last_login"] = int(now * 1000)
        _save_store(data)
        return public_user(user), token


def logout(token: str) -> None:
    with _store_lock:
        data = _load_store()
        if data["sessions"].pop(token, None) is not None:
            _save_store(data)


def user_from_token(token: Optional[str]) -> Optional[Dict[str, Any]]:
    if not token:
        return None
    with _store_lock:
        data = _load_store()
        sess = data["sessions"].get(token)
        if not sess:
            return None
        if sess.get("expires", 0) < time.time():
            data["sessions"].pop(token, None)
            _save_store(data)
            return None
        user = data["users"].get(sess.get("user"))
        if not user or user.get("disabled"):
            return None
        # 滑动过期
        sess["expires"] = time.time() + config.SESSION_TTL_SECS
        return public_user(user)


def list_users() -> List[Dict[str, Any]]:
    data = _load_store()
    users = [public_user(u) for u in data["users"].values()]
    users.sort(key=lambda u: (u["role"] != "admin", u["username"]), reverse=True)
    return users


def update_user(username: str, patch: Dict[str, Any]) -> Dict[str, Any]:
    with _store_lock:
        data = _load_store()
        user = data["users"].get(canonical_username(username))
        if user is None:
            raise KeyError(username)
        if patch.get("role") in ("admin", "user"):
            user["role"] = patch["role"]
        if isinstance(patch.get("display_name"), str) and patch["display_name"].strip():
            user["display_name"] = patch["display_name"].strip()[:40]
        if isinstance(patch.get("disabled"), bool):
            user["disabled"] = patch["disabled"]
        if isinstance(patch.get("color"), str) and re.match(r"^#[0-9a-fA-F]{6}$", patch["color"]):
            user["color"] = patch["color"]
        if patch.get("password"):
            salt = secrets.token_bytes(16)
            user["salt"] = salt.hex()
            user["hash"] = _hash_password(patch["password"], salt)
        _save_store(data)
        return public_user(user)


def get_user(username: str) -> Optional[Dict[str, Any]]:
    data = _load_store()
    user = data["users"].get(canonical_username(username))
    return public_user(user) if user else None


def count_users() -> int:
    return len(_load_store()["users"])


def migrate_store() -> int:
    """启动时一次性归一化历史数据。

    旧版本用户名按原样(可含大写)存储、ACL 也可能含混合大小写键;
    这里把 users / sessions 的键统一成 canonical 形式。仅在发现
    非 canonical 键时落盘。返回迁移的条目数(观测用)。
    """
    with _store_lock:
        data = _load_store()
        moved = 0
        users: Dict[str, Any] = {}
        for raw_name, user in data["users"].items():
            key = canonical_username(raw_name)
            if not key:
                continue
            if key in users:
                # 极端情况: 历史上大小写不同的重复账号, 保留先出现的
                continue
            user["username"] = key
            users[key] = user
            if key != raw_name:
                moved += 1
        data["users"] = users

        sessions: Dict[str, Any] = {}
        for token, sess in data["sessions"].items():
            user_key = canonical_username(sess.get("user"))
            if user_key and user_key in users:
                sess["user"] = user_key
                sessions[token] = sess
        data["sessions"] = sessions
        if moved:
            _save_store(data)
        return moved


# ---------------------------------------------------------------- 白板权限
def board_role(user: Optional[Dict[str, Any]], meta: Dict[str, Any]) -> Optional[str]:
    """计算用户在某白板上的有效角色; None=无权访问。

    统一判定链(全系统唯一角色来源, REST/WS/前端预览均与此一致):
        1. 系统管理员        → owner
        2. 白板所有者        → owner
        3. 成员授权 acl      → 该成员被授予的角色
        4. 邀请链接默认角色  → public_role(仅当用户不在 acl 中时兜底)
        5. 都不满足          → None(拒绝访问)

    所有用户名比较都走 canonical_username, 大小写不敏感。
    """
    if user is None:
        return None
    username = canonical_username(user.get("username"))
    if not username:
        return None
    if user.get("role") == "admin":
        return "owner"
    if canonical_username(meta.get("owner")) == username:
        return "owner"
    acl = normalize_acl(meta.get("acl"))
    role = acl.get(username)
    if role in VALID_ROLES:
        return role
    public_role = meta.get("public_role")
    if public_role in VALID_ROLES:
        return public_role
    return None


def role_at_least(role: Optional[str], required: str) -> bool:
    if role is None:
        return False
    return ROLE_ORDER.get(role, 0) >= ROLE_ORDER.get(required, 99)


# ---------------------------------------------------------------- 能力判定
# 角色 → 能力的唯一映射, 前后端各页面与 WS 实时协作都以此为准:
#   viewer    可见(查看白板/历史/导出/聊天记录)
#   commenter viewer + 可在协作聊天发言
#   editor    commenter + 可绘制编辑画布/撤销重做/存缩略图
#   owner     editor + 可管理成员角色/公开角色/删除白板/压缩历史
def can_view(role: Optional[str]) -> bool:
    return role_at_least(role, "viewer")


def can_comment(role: Optional[str]) -> bool:
    return role_at_least(role, "commenter")


def can_edit(role: Optional[str]) -> bool:
    return role_at_least(role, "editor")


def can_manage(role: Optional[str]) -> bool:
    return role_at_least(role, "owner")


# ---------------------------------------------------------------- FastAPI 依赖
def _extract_token(request: Request) -> Optional[str]:
    token = request.headers.get("x-auth-token")
    if not token:
        token = request.query_params.get("token")
    return token


def current_user_optional(request: Request) -> Optional[Dict[str, Any]]:
    return user_from_token(_extract_token(request))


def current_user(request: Request) -> Dict[str, Any]:
    user = user_from_token(_extract_token(request))
    if user is None:
        raise HTTPException(status_code=401, detail="未登录或会话已过期")
    return user


def require_admin(user: Dict[str, Any] = Depends(current_user)) -> Dict[str, Any]:
    if user.get("role") != "admin":
        raise HTTPException(status_code=403, detail="需要管理员权限")
    return user
