#!/usr/bin/env python3
"""Format bounded window data from platform tools or user-provided JSON.

No platform database, environment discovery, or transcript files are read.
Without --out this command only writes JSON to stdout.
"""
import argparse
import hashlib
import json
import ntpath
import os
import re
import sys
import uuid
from datetime import datetime
from pathlib import Path

MAX_INPUT_BYTES = 1024 * 1024
MAX_WINDOWS = 500
PLATFORMS = {p.lower(): p for p in ("Codex", "Claude", "Hermes", "OpenClaw", "ChatGPT")}
RECORD_FIELDS = {"platform", "id", "title", "cwd", "archived", "pinned", "status", "summary",
                 "updated_at", "project_id", "first_ask", "last_ask", "last_answer"}
COVERAGE_FIELDS = {"complete", "limit", "archived_included", "notes", "fetched_at"}
ID_PATTERN = re.compile(r"^[A-Za-z0-9_.:-]{1,128}$")
SECRET_FIELD = re.compile(
    r"(?i)(\b(?:api[_ -]?key|access[_ -]?token|refresh[_ -]?token|client[_ -]?secret|password|passwd|authorization)\b|密码|口令|密钥)"
    r"\s*[:=：]\s*(?:\"[^\"]*\"|'[^']*'|(?:Bearer\s+)?[^\s,;，；]+)")
PRIVATE_KEY = re.compile(r"-----BEGIN [^-]*PRIVATE KEY-----[\s\S]*?-----END [^-]*PRIVATE KEY-----")


class InputError(ValueError):
    pass


def redact(value, limit=1200):
    value = PRIVATE_KEY.sub("[私钥已隐藏]", value)
    value = SECRET_FIELD.sub(lambda match: match.group(1) + "=[已隐藏]", value)
    value = re.sub(r"(?i)\bBearer\s+[A-Za-z0-9._~+/=-]+", "Bearer [已隐藏]", value)
    value = re.sub(r"\b(?:sk-[A-Za-z0-9_-]{16,}|gh[pousr]_[A-Za-z0-9_]{16,}|github_pat_[A-Za-z0-9_]{16,})\b", "[凭证已隐藏]", value)
    value = " ".join(value.split())
    value = "".join(c for c in value if c.isprintable())
    return value if len(value) <= limit else value[:limit] + "…"


def text(value, field, limit=1200, required=False):
    if value is None and not required:
        return ""
    if not isinstance(value, str) or (required and not value.strip()):
        raise InputError(field + " 必须是" + ("非空" if required else "") + "字符串")
    return redact(value, limit)


def normalize_path(value):
    if not isinstance(value, str) or not value.strip() or any(ord(c) < 32 for c in value):
        raise InputError("cwd 必须是绝对目录路径")
    value = value.strip()
    if re.match(r"^[A-Za-z]:[/\\]", value) or value.startswith(("\\\\", "//")):
        return ntpath.normcase(ntpath.normpath(value.replace("/", "\\"))).rstrip("\\")
    if value.startswith("/"):
        return os.path.normpath(value).rstrip("/") or "/"
    raise InputError("cwd 必须是绝对目录路径")


def in_project(cwd, project):
    """Canonical lexical comparison for Windows and POSIX absolute paths."""
    child, parent = normalize_path(cwd), normalize_path(project)
    sep = "\\" if "\\" in parent or re.match(r"^[a-z]:", parent) else "/"
    return child == parent or child.startswith(parent.rstrip(sep) + sep)


def read_input(path):
    path = Path(path)
    with path.open("rb") as handle:
        raw = handle.read(MAX_INPUT_BYTES + 1)
    if len(raw) > MAX_INPUT_BYTES:
        raise InputError("输入超过 1MB；请先在平台工具侧缩小项目范围和摘要")
    def reject_constant(value):
        raise InputError("JSON 不接受 NaN 或 Infinity 数值")
    try:
        return json.loads(raw.decode("utf-8-sig"), parse_constant=reject_constant), hashlib.sha256(raw).hexdigest()
    except (UnicodeDecodeError, json.JSONDecodeError):
        raise InputError("输入必须是 UTF-8 JSON 窗口资料；不接受数据库或聊天日志") from None


def parse_source(data):
    legacy = isinstance(data, list)
    if legacy:
        records = data
        source = "旧窗口列表导入（覆盖范围未声明）"
        coverage = {"complete": False, "archived_included": None, "notes": "仅格式兼容；未读取旧列表引用的任何文件"}
    elif isinstance(data, dict):
        allowed = {"schema_version", "source", "coverage", "windows"}
        if set(data) - allowed:
            raise InputError("输入顶层存在未支持字段；请导出最小窗口资料，不要保存完整工具响应")
        if type(data.get("schema_version")) is not int or data["schema_version"] != 1:
            raise InputError("schema_version 必须为整数 1")
        source = text(data.get("source"), "source", 240, required=True)
        coverage = data.get("coverage")
        if not isinstance(coverage, dict) or set(coverage) - COVERAGE_FIELDS:
            raise InputError("coverage 必须是只含覆盖范围字段的对象")
        if type(coverage.get("complete")) is not bool:
            raise InputError("coverage.complete 必须为 true 或 false")
        if "archived_included" in coverage and coverage["archived_included"] is not None and type(coverage["archived_included"]) is not bool:
            raise InputError("coverage.archived_included 必须为布尔值或 null")
        if "limit" in coverage and (type(coverage["limit"]) is not int or not 0 <= coverage["limit"] <= MAX_WINDOWS):
            raise InputError("coverage.limit 必须为 0 到 500 的整数")
        coverage = dict(coverage)
        for key in ("notes", "fetched_at"):
            if key in coverage:
                coverage[key] = text(coverage[key], "coverage." + key, 500)
        records = data.get("windows")
    else:
        raise InputError("输入必须是窗口资料对象或旧窗口列表")
    if not isinstance(records, list) or len(records) > MAX_WINDOWS:
        raise InputError("windows 必须是最多 500 条记录的数组")
    return records, source, coverage, legacy


def prepare_snapshot(data, project, include_archived=False, platform="all"):
    records, source, coverage, legacy = parse_source(data)
    selected, seen = [], set()
    excluded = {"outside_project": 0, "archived": 0, "other_platform": 0}
    for index, row in enumerate(records, 1):
        if not isinstance(row, dict):
            raise InputError(f"第 {index} 条窗口记录必须是对象")
        if not legacy and set(row) - RECORD_FIELDS:
            raise InputError(f"第 {index} 条含未支持字段；只保留窗口元数据和必要摘要")
        raw_platform = row.get("platform", "Codex")
        if not isinstance(raw_platform, str) or raw_platform.lower() not in PLATFORMS:
            raise InputError(f"第 {index} 条 platform 不受支持")
        normalized_platform = PLATFORMS[raw_platform.lower()]
        identity = row.get("id")
        if not isinstance(identity, str) or not ID_PATTERN.fullmatch(identity):
            raise InputError(f"第 {index} 条缺少合法稳定聊天 ID")
        title = text(row.get("title"), f"第 {index} 条 title", 300, required=True)
        cwd = row.get("cwd")
        if not in_project(cwd, project):
            excluded["outside_project"] += 1
            continue
        # Resolve only paths already lexically inside the selected project. This
        # prevents a symlink/junction to another project from being attributed here.
        if os.name == "nt" or (isinstance(cwd, str) and cwd.startswith("/") and not cwd.startswith("//")):
            if not in_project(str(Path(cwd).resolve()), str(Path(project).resolve())):
                excluded["outside_project"] += 1
                continue
        for key in ("archived", "pinned"):
            if row.get(key) is not None and type(row[key]) is not bool:
                raise InputError(f"第 {index} 条 {key} 必须为布尔值或 null")
        if row.get("archived") and not include_archived:
            excluded["archived"] += 1
            continue
        if platform != "all" and normalized_platform.lower() != platform:
            excluded["other_platform"] += 1
            continue
        unique_key = (normalized_platform, identity)
        if unique_key in seen:
            raise InputError(f"第 {index} 条与前面记录重复，请按稳定聊天 ID 核对来源")
        seen.add(unique_key)
        item = {"platform": normalized_platform, "id": identity, "title": title, "cwd": cwd,
                "archived": row.get("archived"), "pinned": row.get("pinned"),
                "status": text(row.get("status"), "status", 80),
                "summary": text(row.get("summary"), "summary", 1200)}
        for key in ("first_ask", "last_ask", "last_answer", "project_id"):
            if row.get(key) is not None:
                item[key] = text(row[key], key, 600 if key != "project_id" else 128)
        if "updated_at" in row:
            value = row["updated_at"]
            if not isinstance(value, (str, int, float)) or isinstance(value, bool):
                raise InputError("updated_at 必须是字符串或数值")
            item["updated_at"] = text(value, "updated_at", 80) if isinstance(value, str) else value
        selected.append(item)
    return {"schema_version": 1, "ok": True, "project": project, "source": source,
            "coverage": coverage, "coverage_independently_verified": False,
            "imported_records": len(records), "matched_records": len(selected), "excluded": excluded,
            "windows": selected,
            "notes": ["只整理输入资料，不读取平台数据库或会话文件。",
                      "覆盖范围来自输入声明；窗口数量不代表整个项目的全部聊天。",
                      "平台加载状态不是业务完成状态；本工具不判断改名、归档或新建。",
                      "仅对常见明确凭证形式做辅助脱敏，输入前仍须筛选必要信息。"]}


def markdown(snapshot):
    def escape(value):
        return str(value).replace("|", "\\|").replace("<", "&lt;").replace(">", "&gt;")
    lines = ["# 项目窗口目录", "", f"项目：`{snapshot['project']}`", "",
             "来源：" + escape(snapshot["source"]),
             f"本次输入 {snapshot['imported_records']} 条，匹配 {snapshot['matched_records']} 条。",
             "覆盖范围：" + escape(json.dumps(snapshot["coverage"], ensure_ascii=False)), ""]
    lines += ["- " + n for n in snapshot["notes"]]
    lines += ["", "| 平台 | 稳定聊天 ID | 原标题 | 加载状态 | 必要摘要 |", "|---|---|---|---|---|"]
    for w in snapshot["windows"]:
        brief = w["summary"] or w.get("last_answer", "")
        lines.append("| " + " | ".join(escape(w[k]) for k in ("platform", "id", "title", "status")) + " | " + escape(brief) + " |")
    return "\n".join(lines) + "\n"


def write_outputs(snapshot, directory):
    directory = Path(directory)
    directory.mkdir(parents=True, exist_ok=True)
    name = "窗口目录-" + datetime.now().strftime("%Y%m%d-%H%M%S") + "-" + uuid.uuid4().hex[:8]
    md, js = directory / (name + ".md"), directory / (name + ".json")
    with md.open("x", encoding="utf-8", newline="\n") as handle:
        handle.write(markdown(snapshot))
    with js.open("x", encoding="utf-8", newline="\n") as handle:
        json.dump(snapshot, handle, ensure_ascii=False, indent=2, allow_nan=False)
        handle.write("\n")
    return {"markdown": str(md), "json": str(js)}


def main(argv=None):
    if hasattr(sys.stdout, "reconfigure"):
        sys.stdout.reconfigure(encoding="utf-8")
    parser = argparse.ArgumentParser(description="整理平台工具或用户明确提供的项目窗口资料；不扫描数据库或完整聊天")
    parser.add_argument("--project", required=True, help="实际项目根目录")
    parser.add_argument("--input", help="UTF-8 最小窗口 JSON；来源为平台工具或用户明确提供的资料")
    parser.add_argument("--out", help="可选输出目录；不传则只向标准输出返回 JSON")
    parser.add_argument("--include-archived", action="store_true")
    parser.add_argument("--platform", choices=["all", *PLATFORMS.keys()], default="all")
    args = parser.parse_args(argv)
    try:
        if not args.input:
            raise InputError("未提供 --input；请先用平台工具取得本项目窗口资料，或使用用户明确提供的资料；来源缺失不等于零窗口")
        project = str(Path(args.project).resolve())
        if not Path(project).is_dir():
            raise InputError("指定项目目录不存在")
        data, digest = read_input(args.input)
        snapshot = prepare_snapshot(data, project, args.include_archived, args.platform)
        snapshot["input_sha256"] = digest
        if args.out:
            paths = write_outputs(snapshot, args.out)
            result = {"ok": True, "matched_records": snapshot["matched_records"],
                      "coverage": snapshot["coverage"], "coverage_independently_verified": False, **paths}
        else:
            result = snapshot
        print(json.dumps(result, ensure_ascii=False, allow_nan=False))
        return 0
    except (InputError, OSError, ValueError) as exc:
        print(json.dumps({"ok": False, "verification": "unverified", "error": redact(str(exc), 600)}, ensure_ascii=False))
        return 2


if __name__ == "__main__":
    raise SystemExit(main())
