#!/usr/bin/env python3

import argparse
import fnmatch
import pathlib
import re
import sys

SKIP_SUFFIXES = {".png", ".jpg", ".jpeg", ".gif", ".pdf", ".ico", ".bin", ".o", ".so", ".a"}


def iter_files(root: pathlib.Path, targets: list[str]):
    for target in targets:
        path = root / target
        if not path.exists():
            continue
        if path.is_file():
            yield path
            continue
        for child in sorted(path.rglob("*")):
            if child.is_file():
                yield child


def matches_filters(relative_path: str, include: str | None, exclude: str | None) -> bool:
    basename = pathlib.PurePosixPath(relative_path).name
    if include and not (fnmatch.fnmatch(relative_path, include) or fnmatch.fnmatch(basename, include)):
        return False
    if exclude and (fnmatch.fnmatch(relative_path, exclude) or fnmatch.fnmatch(basename, exclude)):
        return False
    return True


def command_content(args: argparse.Namespace) -> int:
    root = pathlib.Path(args.root).resolve()
    pattern = re.compile(args.pattern)

    for path in iter_files(root, args.roots):
        relative_path = path.relative_to(root)
        relative_str = str(relative_path)
        if not matches_filters(relative_str, args.include, args.exclude):
            continue
        if path.suffix.lower() in SKIP_SUFFIXES:
            continue
        try:
            content = path.read_text(encoding="utf-8")
        except UnicodeDecodeError:
            content = path.read_text(encoding="utf-8", errors="ignore")
        matched = False
        for lineno, line in enumerate(content.splitlines(), start=1):
            if pattern.search(line):
                print(f"{relative_str}:{lineno}:{line}")
                matched = True
        if matched:
            continue
    return 0


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser()
    parser.add_argument("--root", default=".")
    subparsers = parser.add_subparsers(dest="command", required=True)

    content = subparsers.add_parser("content")
    content.add_argument("--roots", nargs="+", required=True)
    content.add_argument("--include")
    content.add_argument("--exclude")
    content.add_argument("--pattern", required=True)
    content.set_defaults(func=command_content)

    return parser


def main() -> int:
    parser = build_parser()
    args = parser.parse_args()
    return args.func(args)


if __name__ == "__main__":
    sys.exit(main())
