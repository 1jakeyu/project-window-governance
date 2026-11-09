#!/usr/bin/env python3
"""本地任务卡工具：同机锁、显式状态、稳定回执及可重放日志。仅 Python 标准库。"""
import argparse
import base64
import contextlib
import hashlib
import json
import os
import re
import socket
import stat
import sys
import time
import unicodedata
import uuid
from datetime import datetime
from pathlib import Path

AGENT_STATUSES = ["待启动", "进行中", "有阻塞", "已暂停", "待验收"]
USER_STATUSES = ["已完成", "已取消"]
STATUS_ORDER = ["进行中", "有阻塞", "待验收", "待启动", "已暂停", "已完成", "已取消"]
VERIFICATIONS = ["unverified", "passed", "failed", "mixed"]
CHECK_RESULTS = VERIFICATIONS + ["skipped"]
MAX_TEXT = 4000
MAX_BYTES = 64 * 1024
MAX_CARD_BYTES = 512 * 1024
MAX_JOURNAL_BYTES = 2 * 1024 * 1024
MAX_ENTRIES = 10000
CARD_RE = re.compile(r"^(T\d{3,})-.+\.md$")
TASK_RE = re.compile(r"T\d{3,}\Z")
TEMPLATE = Path(__file__).resolve().parent.parent / "templates" / "task-card.md"
HANDOFF_HEADING = "## 交接记录"
TRANSITIONS = {
    "待启动": {"进行中", "已暂停", "已取消"},
    "进行中": {"有阻塞", "已暂停", "待验收", "已取消"},
    "有阻塞": {"进行中", "待启动", "已暂停", "已取消"},
    "待验收": {"进行中", "有阻塞", "已暂停", "已完成", "已取消"},
    "已暂停": set(), "已完成": set(), "已取消": set(),
}


class TaskError(Exception):
    def __init__(self, message, **details):
        super().__init__(message)
        self.details = details


def fail(message, **details):
    raise TaskError(message, **details)


def now():
    return datetime.now().astimezone()


def sha(data):
    return hashlib.sha256(data).hexdigest()


def json_bytes(value):
    return (json.dumps(value, ensure_ascii=False, sort_keys=True, indent=2) + "\n").encode("utf-8")


def fingerprint(value):
    return sha(json.dumps(value, ensure_ascii=False, sort_keys=True, separators=(",", ":")).encode("utf-8"))


def text_field(value, label, allow_empty=False, single=False, limit=MAX_TEXT):
    if not isinstance(value, str) or len(value) > limit or (not allow_empty and not value.strip()):
        fail(f"{label} 必须是{'0' if allow_empty else '1'}-{limit}字文字")
    for ch in value:
        if unicodedata.category(ch) in ("Cc", "Cf", "Zl", "Zp"):
            if not single and ch in ("\n", "\r", "\t"):
                continue
            fail(f"{label} 含不允许的换行或控制字符")
    return value


def single_field(value, label, allow_empty=False, limit=MAX_TEXT):
    return text_field(value, label, allow_empty, True, limit)


def check_no_links(path):
    path = Path(os.path.abspath(path))
    for item in reversed((path, *path.parents)):
        try:
            info = item.lstat()
        except FileNotFoundError:
            continue
        if stat.S_ISLNK(info.st_mode) or getattr(info, "st_file_attributes", 0) & 0x400:
            fail("拒绝符号链接或 Windows 联接点", path=str(item))
    return path


def task_directory(raw):
    single_field(str(raw), "任务目录")
    if ".." in Path(raw).parts:
        fail("任务目录不能包含 ..")
    return check_no_links(raw)


def within(directory, relative):
    relative = Path(relative)
    if relative.is_absolute() or relative.drive or ".." in relative.parts:
        fail("文件路径越出任务目录")
    path = check_no_links(directory / relative)
    if not path.is_relative_to(directory):
        fail("文件路径越出任务目录")
    return path


def ensure_directory(path):
    check_no_links(path)
    path.mkdir(parents=True, exist_ok=True)
    check_no_links(path)
    if not path.is_dir():
        fail("所需目录不是普通目录", path=str(path))


def read_bytes(path, maximum=MAX_CARD_BYTES):
    check_no_links(path)
    info = path.stat()
    if not stat.S_ISREG(info.st_mode) or info.st_size > maximum:
        fail("文件类型或大小超出允许范围", path=str(path))
    with path.open("rb") as handle:
        result = handle.read(maximum + 1)
    if len(result) > maximum:
        fail("文件读取超出允许范围", path=str(path))
    return result


def atomic_write(path, content, expected=None):
    """持锁期间使用；替换前复核旧字节。失败暂存文件保留，不自动删除。"""
    check_no_links(path)
    ensure_directory(path.parent)
    if expected is None:
        if path.exists():
            fail("目标已存在，拒绝覆盖", path=str(path))
    elif not path.exists() or read_bytes(path, MAX_JOURNAL_BYTES) != expected:
        fail("文件已发生变化，停止覆盖", path=str(path))
    temp = check_no_links(path.with_name(".stage-" + uuid.uuid4().hex + ".tmp"))
    with temp.open("xb") as handle:
        handle.write(content)
        handle.flush()
        os.fsync(handle.fileno())
    check_no_links(path)
    if expected is None:
        if path.exists():
            fail("发布前目标已出现，保留暂存文件", path=str(path), staged=str(temp))
    elif not path.exists() or read_bytes(path, MAX_JOURNAL_BYTES) != expected:
        fail("发布前检测到外部修改，保留暂存文件", path=str(path), staged=str(temp))
    os.replace(temp, path)


@contextlib.contextmanager
def directory_lock(directory, timeout):
    ensure_directory(directory)
    path = within(directory, ".tasks.lock")
    handle = path.open("a+b")
    acquired = False
    try:
        if path.stat().st_size == 0:
            handle.write(b"0")
            handle.flush()
        deadline = time.monotonic() + timeout
        while True:
            try:
                if os.name == "nt":
                    import msvcrt
                    handle.seek(0)
                    msvcrt.locking(handle.fileno(), msvcrt.LK_NBLCK, 1)
                else:
                    import fcntl
                    fcntl.flock(handle.fileno(), fcntl.LOCK_EX | fcntl.LOCK_NB)
                acquired = True
                break
            except OSError:
                if time.monotonic() >= deadline:
                    fail("任务目录正在被其他进程写入，等待超时；本次未取得写锁", code="lock_timeout")
                time.sleep(0.05)
        yield
    finally:
        if acquired:
            if os.name == "nt":
                import msvcrt
                handle.seek(0)
                msvcrt.locking(handle.fileno(), msvcrt.LK_UNLCK, 1)
            else:
                import fcntl
                fcntl.flock(handle.fileno(), fcntl.LOCK_UN)
        handle.close()


class Card:
    def __init__(self, path):
        self.path = path
        self.raw = read_bytes(path)
        text = self.raw.decode("utf-8")
        match = re.match(r"\A(\ufeff?---\r?\n)(.*?)(\r?\n---(?:\r?\n|$))", text, re.S)
        if not match:
            fail(f"{path.name} 缺少完整的 --- 属性区")
        self.opening, header, self.closing = match.groups()
        self.header_lines = header.split("\n")
        self.body = text[match.end():]
        self.eol = "\r\n" if "\r\n" in self.opening else "\n"
        self.meta = {}
        self.positions = {}
        for index, raw_line in enumerate(self.header_lines):
            line = raw_line[:-1] if raw_line.endswith("\r") else raw_line
            if not line.strip() or line.lstrip().startswith("#"):
                single_field(line, "属性注释", allow_empty=True)
                continue
            if line[0].isspace() or ":" not in line:
                fail(f"{path.name} 属性区不是支持的单行 key: value 格式")
            key, value = line.split(":", 1)
            single_field(key, "属性名")
            single_field(value, f"属性 {key}", allow_empty=True)
            key, value = key.strip(), value.strip()
            if not key or key in self.meta:
                fail(f"{path.name} 存在空或重复属性")
            self.meta[key] = value
            self.positions[key] = index
        filename_id = CARD_RE.fullmatch(path.name)
        if not filename_id or self.meta.get("任务ID") != filename_id.group(1):
            fail(f"{path.name} 的任务ID与文件名不一致")
        if self.meta.get("状态") not in TRANSITIONS:
            fail(f"{path.name} 的状态未知，拒绝猜测")

    def render(self, updates=None, body=None):
        lines = list(self.header_lines)
        for key, value in (updates or {}).items():
            single_field(key, "属性名")
            single_field(value, f"属性 {key}", allow_empty=True)
            if key in self.positions:
                index = self.positions[key]
                tail = "\r" if lines[index].endswith("\r") else ""
                lines[index] = f"{key}: {value}" + tail
            else:
                if self.eol == "\r\n" and lines and not lines[-1].endswith("\r"):
                    lines[-1] += "\r"
                lines.append(f"{key}: {value}")
        result = self.opening + "\n".join(lines) + self.closing + (self.body if body is None else body)
        encoded = result.encode("utf-8")
        if len(encoded) > MAX_CARD_BYTES:
            fail("任务卡超过512KB，请先人工核对范围")
        return encoded


def entries(directory):
    check_no_links(directory)
    if not directory.exists():
        return []
    if not directory.is_dir():
        fail("任务目录不是目录")
    result = []
    with os.scandir(directory) as iterator:
        for item in iterator:
            if len(result) >= MAX_ENTRIES:
                fail("指定目录条目超过10000，停止读取")
            result.append(Path(item.path))
    return sorted(result, key=lambda p: p.name)


def cards(directory):
    found = {}
    for item in entries(directory):
        match = CARD_RE.fullmatch(item.name)
        if not match:
            continue
        check_no_links(item)
        if not item.is_file():
            fail("任务卡路径不是普通文件", path=str(item))
        task_id = match.group(1)
        if task_id in found:
            fail("发现重复任务ID，停止处理全部冲突卡", code="duplicate_task_id", task_id=task_id,
                 paths=[str(found[task_id]), str(item)])
        found[task_id] = item
    return found


def find_card(directory, task_id):
    path = cards(directory).get(task_id)
    if path is None:
        fail(f"指定任务目录中找不到 {task_id}")
    return Card(path)


def load_device(directory):
    path = within(directory, "_config.json")
    config = json.loads(read_bytes(path, MAX_BYTES)) if path.exists() else {}
    if not isinstance(config, dict):
        fail("_config.json 必须是对象")
    device = config.get("device_id") or os.environ.get("TASK_DEVICE_ID") or socket.gethostname().split(".")[0]
    return single_field(device, "device_id", limit=80)


def require_acceptance(card):
    # 删除HTML注释后只识别恰好一个二级验收章节，其他章节的复选框不算。
    body = re.sub(r"<!--[\s\S]*?-->", "", card.body)
    lines = body.splitlines()
    positions = [i for i, line in enumerate(lines) if line.strip() == "## 验收标准"]
    if len(positions) != 1:
        fail("必须有且仅有一个 ## 验收标准 章节，不能开工")
    section = []
    for line in lines[positions[0] + 1:]:
        if re.match(r"^##\s+", line):
            break
        section.append(line)
    items = [re.match(r"^\s*-\s+\[[ xX]\]\s+(.+?)\s*$", line) for line in section]
    values = [m.group(1).strip() for m in items if m]
    if not values or not any(v not in ("待填写", "待补充", "TODO", "TBD", "...", "…") for v in values):
        fail("验收标准为空或仍为占位，不能开工")


def validate_transition(card, target, by_user=False, resume=False):
    current = card.meta["状态"]
    if target not in TRANSITIONS:
        fail("状态无效")
    if resume:
        if not by_user:
            fail("恢复需已有用户明确确认，再使用 --by-user；该标志不验证身份")
        if current not in ("已暂停", "已完成", "已取消") or target != "待启动":
            fail("resume 仅将已暂停、已完成或已取消恢复为待启动")
        return
    if target in USER_STATUSES and not by_user:
        fail("完成或取消需已有用户明确确认，再使用 --by-user；该标志不验证身份")
    if current in ("已暂停", "已完成", "已取消") and target != current:
        fail("暂停或终态不能直接改写，请经用户确认使用 resume，再开工")
    if target != current and target not in TRANSITIONS[current]:
        fail(f"不允许从「{current}」直接转为「{target}」")
    if target == "进行中":
        require_acceptance(card)


def status_updates(card, target, window=None, stamp=None):
    updates = {"状态": target, "更新时间": stamp or now().strftime("%Y-%m-%d %H:%M")}
    if window is not None:
        updates["负责窗口"] = window
    return updates


def operation_paths(directory, receipt_id):
    key = sha(receipt_id.encode("utf-8"))
    return (within(directory, ".operations/" + key + ".json"),
            within(directory, ".operations/" + key + ".applied.json"))


def read_operation(path):
    op = json.loads(read_bytes(path, MAX_JOURNAL_BYTES))
    expected_keys = {"version", "request", "request_hash", "payload", "receipt_hash", "receipt_path",
                     "card_path", "before_hash", "after_hash", "after_card"}
    if not isinstance(op, dict) or set(op) != expected_keys or op["version"] != 1:
        fail("恢复记录格式无效，保留现场", journal=str(path))
    if not isinstance(op["request"], dict) or not isinstance(op["payload"], dict):
        fail("恢复记录内容无效")
    if fingerprint(op["request"]) != op["request_hash"] or sha(json_bytes(op["payload"])) != op["receipt_hash"]:
        fail("恢复记录内容校验失败，保留现场", journal=str(path))
    after = base64.b64decode(op["after_card"], validate=True)
    if sha(after) != op["after_hash"] or len(after) > MAX_CARD_BYTES:
        fail("恢复记录卡片校验失败", journal=str(path))
    request = op["request"]
    if not TASK_RE.fullmatch(request.get("task_id", "")) or op["payload"].get("task_id") != request["task_id"]:
        fail("恢复记录任务ID不一致")
    if op["payload"].get("receipt_id") != request.get("receipt_id"):
        fail("恢复记录回执ID不一致")
    expected_name = sha(request["receipt_id"].encode("utf-8"))
    if path.name != expected_name + ".json":
        fail("恢复记录文件名不匹配")
    if Path(op["card_path"]).name != op["card_path"] or not op["card_path"].startswith(request["task_id"] + "-"):
        fail("恢复记录任务路径不合法")
    if op["receipt_path"] != "回执/" + request["task_id"] + "-" + expected_name + ".json":
        fail("恢复记录回执路径不合法")
    return op, after


def assert_no_pending(directory, task_id, except_id=None):
    operations = within(directory, ".operations")
    for path in entries(operations):
        if not re.fullmatch(r"[0-9a-f]{64}\.json", path.name):
            continue
        marker = within(directory, ".operations/" + path.stem + ".applied.json")
        if marker.exists():
            continue
        op, _ = read_operation(path)
        request = op["request"]
        if request["task_id"] == task_id and request["receipt_id"] != except_id:
            fail("该任务有未完成回执，请先按原编号重试或 recover", code="receipt_pending",
                 receipt_id=request["receipt_id"], journal=str(path))


def apply_operation(directory, journal):
    op, after = read_operation(journal)
    receipt_id = op["request"]["receipt_id"]
    _, marker = operation_paths(directory, receipt_id)
    card = find_card(directory, op["request"]["task_id"])
    if card.path != within(directory, op["card_path"]):
        fail("任务卡路径发生变化，停止恢复", journal=str(journal))
    receipt_path = within(directory, op["receipt_path"])
    encoded = json_bytes(op["payload"])
    expected_marker = {"receipt_id": receipt_id, "request_hash": op["request_hash"],
                       "receipt_hash": op["receipt_hash"], "after_hash": op["after_hash"]}
    if marker.exists():
        if json.loads(read_bytes(marker, MAX_BYTES)) != expected_marker:
            fail("回执完成标记冲突，停止恢复")
        if not receipt_path.exists() or read_bytes(receipt_path, MAX_BYTES) != encoded:
            fail("已确认回执缺失或内容改变，拒绝自动补写")
        return {"ok": True, "replayed": True, "receipt_id": receipt_id,
                "receipt": str(receipt_path), "task_id": op["request"]["task_id"],
                "receipt_status": op["payload"]["task_status"], "current_status": card.meta["状态"]}
    if sha(card.raw) not in (op["before_hash"], op["after_hash"]):
        fail("任务卡已被修改，不能重放未完成回执", code="recovery_conflict", journal=str(journal))
    if receipt_path.exists():
        if read_bytes(receipt_path, MAX_BYTES) != encoded:
            fail("回执目标内容冲突，拒绝覆盖", code="recovery_conflict", receipt=str(receipt_path))
    else:
        atomic_write(receipt_path, encoded)
    if sha(card.raw) == op["before_hash"]:
        atomic_write(card.path, after, expected=card.raw)
    atomic_write(marker, json_bytes(expected_marker))
    return {"ok": True, "replayed": False, "receipt_id": receipt_id, "receipt": str(receipt_path),
            "journal": str(journal), "task_id": op["request"]["task_id"], "状态": op["payload"]["task_status"]}


def cmd_new(args, directory):
    found = cards(directory)
    for path in found.values():
        Card(path)
    next_id = max((int(key[1:]) for key in found), default=0) + 1
    task_id = f"T{next_id:03d}"
    cleaned = re.sub(r'[\\/:*?"<>|\s]+', "-", args.title.strip()).strip("-")[:40] or "未命名"
    path = within(directory, task_id + "-" + cleaned + ".md")
    content = read_bytes(TEMPLATE).decode("utf-8")
    stamp = now().strftime("%Y-%m-%d %H:%M")
    replacements = {"{{ID}}": task_id, "{{TITLE}}": args.title, "{{PRIORITY}}": args.priority,
                    "{{EXECUTOR}}": args.executor, "{{NOW}}": stamp}
    # 一次替换，用户文字不能成为下一轮模板占位符。
    content = re.sub(r"\{\{(?:ID|TITLE|PRIORITY|EXECUTOR|NOW)\}\}", lambda m: replacements[m.group()], content)
    if len(content.encode("utf-8")) > MAX_CARD_BYTES:
        fail("新任务卡超出大小限制")
    atomic_write(path, content.encode("utf-8"))
    return {"ok": True, "task_id": task_id, "path": str(path)}


def cmd_status(args, directory):
    card = find_card(directory, args.task_id)
    assert_no_pending(directory, args.task_id)
    target = "进行中" if args.command == "start" else "待启动" if args.command == "resume" else args.status
    validate_transition(card, target, by_user=getattr(args, "by_user", False), resume=args.command == "resume")
    window = args.window
    if target == card.meta["状态"] and (window is None or window == card.meta.get("负责窗口")):
        return {"ok": True, "unchanged": True, "task_id": args.task_id, "状态": target}
    updated = card.render(status_updates(card, target, window))
    atomic_write(card.path, updated, expected=card.raw)
    return {"ok": True, "task_id": args.task_id, "状态": target, "path": str(card.path)}


def split_pipe(raw, parts, label):
    values = raw.split("|", parts - 1)
    if len(values) != parts:
        fail(f"{label} 需要 {parts} 个以 | 分隔的字段")
    # 先验证，不在验证之前 strip 掉恶意换行。
    for value in values:
        single_field(value, label, allow_empty=True)
    return [value.strip() for value in values]


def receipt_request(args):
    checks = []
    for raw in args.check:
        name, result, evidence = split_pipe(raw, 3, "--check")
        if result not in CHECK_RESULTS:
            fail("检查结果无效")
        text_field(name, "检查名称")
        if result in ("passed", "failed") and not evidence:
            fail("passed/failed 检查必须提供证据引用")
        checks.append({"name": name, "result": result, "evidence": evidence})
    if args.verification == "passed" and (not any(c["result"] == "passed" for c in checks)
            or any(c["result"] not in ("passed", "skipped") for c in checks)):
        fail("总体 passed 必须有通过证据，且其余检查只能通过或跳过")
    artifacts = []
    for raw in args.artifact:
        path, description = split_pipe(raw, 2, "--artifact")
        text_field(path, "成果引用路径")
        artifacts.append({"path": path, "description": description})
    return {"receipt_id": args.receipt_id, "task_id": args.task_id, "status": args.status,
            "summary": text_field(args.summary, "摘要"), "verification": args.verification,
            "next": text_field(args.next, "下一步", allow_empty=True), "window": args.window,
            "checks": checks, "artifacts": artifacts}


def append_handoff(body, line, eol):
    matches = list(re.finditer(r"^## 交接记录[ \t]*\r?$", body, re.M))
    if len(matches) > 1:
        fail("交接记录章节重复，停止修改")
    if not matches:
        return body.rstrip("\r\n") + eol + eol + HANDOFF_HEADING + eol + eol + line + eol
    start = matches[0].end()
    following = re.search(r"^##\s+", body[start:], re.M)
    end = start + following.start() if following else len(body)
    return body[:end].rstrip("\r\n") + eol + line + eol + eol + body[end:]


def cmd_receipt(args, directory):
    request = receipt_request(args)
    journal, _ = operation_paths(directory, args.receipt_id)
    if journal.exists():
        op, _ = read_operation(journal)
        if op["request"] != request or op["request_hash"] != fingerprint(request):
            fail("相同 receipt-id 的请求内容不同，拒绝覆盖；更正须明确使用新编号", code="receipt_conflict")
        return apply_operation(directory, journal)
    card = find_card(directory, args.task_id)
    assert_no_pending(directory, args.task_id)
    if card.meta["状态"] in USER_STATUSES:
        fail("已完成或已取消任务不能用自动回执改写，先经用户确认显式恢复")
    validate_transition(card, args.status)
    device = load_device(directory)
    moment = now()
    payload = {"receipt_id": args.receipt_id, "task_id": args.task_id,
               "occurred_at": moment.isoformat(timespec="seconds"), "task_status": args.status,
               "summary": request["summary"], "verification": args.verification, "checks": request["checks"],
               "next_step": request["next"],
               "artifact_refs": [dict(item, device_id=device) for item in request["artifacts"]]}
    if args.window is not None:
        payload["task_ref"] = args.window
    encoded = json_bytes(payload)
    if len(encoded) > MAX_BYTES:
        fail("回执超过64KB，请精简摘要和证据")
    if not any(ch in args.receipt_id for ch in '/\\:'):
        legacy = within(directory, "回执/" + args.receipt_id + ".json")
        if legacy.exists():
            fail("已有同编号旧回执但无恢复记录，拒绝覆盖或重复生成")
    oneline = lambda text: " ".join(text.split())[:200]
    line = (f"- {moment.strftime('%Y-%m-%d %H:%M')}｜{args.window or '未登记窗口'}｜{args.status}｜"
            f"{oneline(args.summary)}｜下一步：{oneline(args.next) or '无'}｜回执：{args.receipt_id}")
    after = card.render(status_updates(card, args.status, args.window, moment.strftime("%Y-%m-%d %H:%M")),
                        append_handoff(card.body, line, card.eol))
    receipt_relative = "回执/" + args.task_id + "-" + sha(args.receipt_id.encode("utf-8")) + ".json"
    op = {"version": 1, "request": request, "request_hash": fingerprint(request), "payload": payload,
          "receipt_hash": sha(encoded), "receipt_path": receipt_relative, "card_path": card.path.name,
          "before_hash": sha(card.raw), "after_hash": sha(after), "after_card": base64.b64encode(after).decode("ascii")}
    atomic_write(journal, json_bytes(op))
    try:
        return apply_operation(directory, journal)
    except (TaskError, OSError) as exc:
        fail("回执尚未全部完成，保留恢复记录；请原参数重试或 recover。" + str(exc),
             code="receipt_incomplete", receipt_id=args.receipt_id, journal=str(journal))


def cmd_recover(args, directory):
    journal, _ = operation_paths(directory, args.receipt_id)
    if not journal.exists():
        fail("找不到指定回执的恢复记录；不会猜测或重建")
    return apply_operation(directory, journal)


def cmd_board(args, directory):
    rows = []
    for task_id, path in cards(directory).items():
        meta = Card(path).meta
        rows.append(dict(任务ID=task_id, 状态=meta["状态"], 优先级=meta.get("优先级", ""),
                         标题=meta.get("标题", ""), 执行者=meta.get("执行者", ""),
                         负责窗口=meta.get("负责窗口", ""), 更新时间=meta.get("更新时间", ""), 文件=path.name))
    rank = {value: i for i, value in enumerate(STATUS_ORDER)}
    rows.sort(key=lambda row: (rank[row["状态"]], row["优先级"], row["任务ID"]))
    if args.json:
        print(json.dumps(rows, ensure_ascii=False, indent=2))
    elif not rows:
        print("指定目录中没有任务卡")
    else:
        for row in rows:
            print(f"{row['任务ID']}  {row['状态']}  {row['优先级']} {row['标题']}  [{row['执行者']}]  {row['负责窗口']}  {row['更新时间']}")
        print(f"\n进行中 {sum(row['状态'] == '进行中' for row in rows)} 张")
    return None


class Parser(argparse.ArgumentParser):
    def error(self, message):
        fail(message, code="argument_error")


def build_parser():
    parser = Parser(description="本地任务卡、显式状态与可重放回执；不验证用户身份，不自动外传")
    parser.add_argument("--dir", default="任务卡", help="明确的本机任务卡目录；不用于跨电脑/网络盘并发")
    parser.add_argument("--lock-timeout", type=float, default=8, help="写锁等待秒数，0-10，默认8")
    sub = parser.add_subparsers(dest="command", required=True)
    p = sub.add_parser("new", help="在同机锁内分配唯一编号并新建卡片")
    p.add_argument("--title", required=True)
    p.add_argument("--priority", default="P2", choices=["P0", "P1", "P2", "P3"])
    p.add_argument("--executor", default="待定")
    p.set_defaults(func=cmd_new)
    for name in ("start", "status", "resume"):
        p = sub.add_parser(name, help={"start": "检查验收标准后进入进行中", "status": "按显式迁移规则改状态", "resume": "有用户确认后将暂停/终态恢复为待启动"}[name])
        p.add_argument("task_id")
        if name == "status":
            p.add_argument("status", choices=AGENT_STATUSES + USER_STATUSES)
        p.add_argument("--window", required=name == "start", help="单行窗口标识或已有名称；不代表工具已核实其存在")
        if name != "start":
            p.add_argument("--by-user", action="store_true", help="记录已有的用户明确确认，不是身份认证或新授权")
        p.set_defaults(func=cmd_status)
    p = sub.add_parser("receipt", help="持久化原请求，再写回执及卡片；重试必须保留原ID和参数")
    p.add_argument("task_id")
    p.add_argument("--receipt-id", required=True, help="同次操作稳定编号，最长200字；重试不得更改")
    p.add_argument("--status", required=True, choices=AGENT_STATUSES)
    p.add_argument("--summary", required=True)
    p.add_argument("--verification", default="unverified", choices=VERIFICATIONS)
    p.add_argument("--next", default="")
    p.add_argument("--window")
    p.add_argument("--check", action="append", default=[], help="名称|结果|证据，可重复")
    p.add_argument("--artifact", action="append", default=[], help="路径|说明，仅保存引用，不读取成果")
    p.set_defaults(func=cmd_receipt)
    p = sub.add_parser("recover", help="仅按既有恢复记录补完，不接受新正文；冲突则停止")
    p.add_argument("--receipt-id", required=True)
    p.set_defaults(func=cmd_recover)
    p = sub.add_parser("board", help="只读看板，不创建目录或锁")
    p.add_argument("--json", action="store_true")
    p.set_defaults(func=cmd_board)
    return parser


def main():
    if hasattr(sys.stdout, "reconfigure"):
        sys.stdout.reconfigure(encoding="utf-8")
    try:
        args = build_parser().parse_args()
        if not 0 <= args.lock_timeout <= 10:
            fail("--lock-timeout 必须为0-10秒")
        for name in ("title", "executor", "window"):
            value = getattr(args, name, None)
            if value is not None:
                single_field(value, name)
        if hasattr(args, "receipt_id"):
            single_field(args.receipt_id, "receipt-id", limit=200)
        if hasattr(args, "task_id"):
            single_field(args.task_id, "task-id", limit=80)
            args.task_id = args.task_id.upper()
            if not TASK_RE.fullmatch(args.task_id):
                fail("task-id 必须是 T001 形式")
        directory = task_directory(args.dir)
        if args.command == "board":
            result = args.func(args, directory)
        else:
            if args.command != "new" and not directory.is_dir():
                fail("指定任务目录不存在，未创建目录")
            with directory_lock(directory, args.lock_timeout):
                result = args.func(args, directory)
        if result is not None:
            print(json.dumps(result, ensure_ascii=False))
        return 0
    except TaskError as exc:
        print(json.dumps(dict(ok=False, error=str(exc), **exc.details), ensure_ascii=False))
        return 1
    except (OSError, ValueError, UnicodeError, KeyError, TypeError, RecursionError) as exc:
        print(json.dumps({"ok": False, "error": "文件或数据处理失败，现场保留", "detail": str(exc)}, ensure_ascii=False))
        return 1


if __name__ == "__main__":
    raise SystemExit(main())