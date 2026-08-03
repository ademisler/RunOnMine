#!/usr/bin/env python3
"""Validate local Markdown links, anchors, index coverage, and known stale claims."""

from __future__ import annotations

import re
import sys
from collections import defaultdict
from pathlib import Path
from urllib.parse import unquote, urlsplit

ROOT = Path(__file__).resolve().parents[2]
IGNORED_PARTS = {".git", "target", "dist", "artifacts", ".venv", "node_modules"}
LINK_RE = re.compile(r"!?\[[^\]]*\]\(([^)]+)\)")
HEADING_RE = re.compile(r"^#{1,6}\s+(.+?)\s*#*\s*$")


def markdown_files() -> list[Path]:
    return sorted(
        path
        for path in ROOT.rglob("*.md")
        if not any(part in IGNORED_PARTS for part in path.relative_to(ROOT).parts)
    )


def github_slug(value: str) -> str:
    value = re.sub(r"<[^>]+>", "", value.strip().lower())
    value = re.sub(r"[`*_~]", "", value)
    value = re.sub(r"[^\w\- ]", "", value, flags=re.UNICODE)
    return re.sub(r"\s+", "-", value)


def anchors(path: Path) -> set[str]:
    counts: defaultdict[str, int] = defaultdict(int)
    result: set[str] = set()
    for line in path.read_text(encoding="utf-8").splitlines():
        match = HEADING_RE.match(line)
        if match is None:
            continue
        base = github_slug(match.group(1))
        duplicate = counts[base]
        counts[base] += 1
        result.add(base if duplicate == 0 else f"{base}-{duplicate}")
    return result


def destination(raw: str) -> str:
    raw = raw.strip()
    if raw.startswith("<") and ">" in raw:
        return raw[1 : raw.index(">")]
    return raw.split(maxsplit=1)[0]


def check_links(files: list[Path]) -> list[str]:
    problems: list[str] = []
    anchor_map = {path.resolve(): anchors(path) for path in files}
    for path in files:
        text = path.read_text(encoding="utf-8")
        for match in LINK_RE.finditer(text):
            raw = destination(match.group(1))
            split = urlsplit(raw)
            if split.scheme or raw.startswith("//"):
                continue
            file_part = unquote(split.path)
            target = (path.parent / file_part).resolve() if file_part else path.resolve()
            if not target.is_relative_to(ROOT):
                problems.append(
                    f"{path.relative_to(ROOT)}: relative link escapes repository {raw}"
                )
                continue
            if not target.exists():
                problems.append(f"{path.relative_to(ROOT)}: missing link target {raw}")
                continue
            fragment = unquote(split.fragment)
            if fragment and target.suffix.lower() == ".md":
                target_anchors = anchor_map.get(target)
                if target_anchors is None:
                    target_anchors = anchors(target)
                if fragment not in target_anchors:
                    problems.append(
                        f"{path.relative_to(ROOT)}: missing Markdown anchor {raw}"
                    )
    return problems


def check_index() -> list[str]:
    index = ROOT / "docs" / "README.md"
    text = index.read_text(encoding="utf-8")
    problems: list[str] = []
    for path in sorted((ROOT / "docs").rglob("*.md")):
        if path == index:
            continue
        relative = path.relative_to(index.parent).as_posix()
        if f"({relative}" not in text:
            problems.append(f"docs/README.md does not link {relative}")
    if "(docs/README.md)" not in (ROOT / "README.md").read_text(encoding="utf-8"):
        problems.append("README.md does not link the documentation index")
    return problems


def check_stale_claims(files: list[Path]) -> list[str]:
    fingerprints = {
        "45% headless line coverage": "coverage is enforced at 70/90/80",
        "ENABLE_GITHUB_HOSTED_PLATFORM_CI": "platform CI has no variable skip guard",
        "opt-in hosted platform matrix": "platform CI is unconditional on pull requests",
    }
    problems: list[str] = []
    for path in files:
        text = path.read_text(encoding="utf-8")
        for fingerprint, correction in fingerprints.items():
            if fingerprint in text:
                problems.append(
                    f"{path.relative_to(ROOT)}: stale phrase {fingerprint!r}; {correction}"
                )
    linux_doc = (ROOT / "docs" / "platforms" / "linux.md").read_text(encoding="utf-8")
    if '"$PWD/target/release/runonmine-desktop"' in linux_doc:
        problems.append(
            "docs/platforms/linux.md: target-specific build must use the target triple directory"
        )
    gates = (ROOT / "acceptance" / "release-gates.toml").read_text(encoding="utf-8")
    if "billing/spending limit" in gates:
        problems.append(
            "acceptance/release-gates.toml: do not infer a billing cause from an unassigned hosted runner"
        )
    return problems




def check_repository_path_examples(files: list[Path]) -> list[str]:
    pattern = re.compile(
        r'(?<![A-Za-z0-9_.-])(?:\./)?((?:scripts|packaging|acceptance)/[A-Za-z0-9_./-]+)'
    )
    problems: list[str] = []
    for path in files:
        for match in pattern.finditer(path.read_text(encoding="utf-8")):
            relative = match.group(1).rstrip(".,;:")
            target = ROOT / relative
            if not target.exists():
                problems.append(
                    f"{path.relative_to(ROOT)}: code example references missing {relative}"
                )
    return problems

def check_tool_inventory() -> list[str]:
    source = (ROOT / "crates" / "runonmine-mcp" / "src" / "lib.rs").read_text(
        encoding="utf-8"
    )
    implemented = set(
        re.findall(
            r'#\[tool\([\s\S]*?\)\]\s*async fn\s+([a-z_]+)\s*\(',
            source,
        )
    )
    tools_doc = (ROOT / "docs" / "tools.md").read_text(encoding="utf-8")
    documented_section = tools_doc.split("## Connector binary trust commands", maxsplit=1)[0]
    documented = set(re.findall(r'`([a-z][a-z0-9_]*_[a-z0-9_]+)`', documented_section))
    problems: list[str] = []
    missing = sorted(implemented - documented)
    extra = sorted(documented - implemented)
    if missing:
        problems.append(f"docs/tools.md is missing MCP tools: {missing}")
    if extra:
        problems.append(f"docs/tools.md lists unknown MCP tools: {extra}")
    return problems

def main() -> int:
    files = markdown_files()
    problems = (
        check_links(files)
        + check_index()
        + check_stale_claims(files)
        + check_repository_path_examples(files)
        + check_tool_inventory()
    )
    if problems:
        for problem in problems:
            print(f"documentation error: {problem}", file=sys.stderr)
        return 1
    print(
        f"Documentation validation passed: {len(files)} Markdown files, "
        "relative links, anchors, index coverage, repository paths, stale claims, "
        "and MCP tool inventory."
    )
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
