#!/usr/bin/env python3
"""Compile quoted Python heredocs embedded in repository shell scripts."""
from __future__ import annotations

import re
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parents[2]
HEREDOC = re.compile(r"<<'(?P<delimiter>PY[A-Z0-9_]*)'")
IGNORED = {'.git', 'target', 'dist', 'artifacts', '.venv', 'node_modules'}


def shell_files() -> list[Path]:
    return sorted(
        path
        for path in ROOT.rglob('*.sh')
        if not any(part in IGNORED for part in path.relative_to(ROOT).parts)
    )


def blocks(path: Path):
    lines = path.read_text(encoding='utf-8').splitlines()
    index = 0
    while index < len(lines):
        match = HEREDOC.search(lines[index])
        if not match:
            index += 1
            continue
        delimiter = match.group('delimiter')
        start = index + 1
        end = start
        while end < len(lines) and lines[end] != delimiter:
            end += 1
        if end == len(lines):
            raise SyntaxError(f'{path.relative_to(ROOT)}:{index + 1}: unterminated {delimiter}')
        yield start + 1, '\n'.join(lines[start:end]) + '\n'
        index = end + 1


def main() -> int:
    checked = 0
    failures: list[str] = []
    for path in shell_files():
        for line, source in blocks(path):
            checked += 1
            try:
                compile(source, f'{path.relative_to(ROOT)}:{line}', 'exec')
            except SyntaxError as error:
                failures.append(str(error))
    if failures:
        print('\n'.join(failures), file=sys.stderr)
        return 1
    print(f'Validated {checked} embedded Python heredocs.')
    return 0


if __name__ == '__main__':
    raise SystemExit(main())
