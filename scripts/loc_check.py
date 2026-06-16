from __future__ import annotations

import argparse
import os
import shutil
import subprocess
import sys
from collections.abc import Iterable, Iterator
from dataclasses import dataclass
from fnmatch import fnmatch
from pathlib import Path
from typing import Final, Literal

LanguageMode = Literal["go", "py", "both"]
Mode = Literal["full", "changed"]

GIT_BIN: Final[str] = shutil.which("git") or "git"
_EXIT_USAGE_ERROR: Final[int] = 2


@dataclass(frozen=True, slots=True)
class Config:
    mode: Mode
    language: LanguageMode
    targets: list[Path]
    excludes: list[str]
    max_loc: int


def _eprint(msg: str) -> None:
    sys.stderr.write(msg + "\n")


def _oprint(msg: str) -> None:
    sys.stdout.write(msg + "\n")


def _run_git(repo_root: Path, args: list[str]) -> str:
    completed = subprocess.run(  # noqa: S603
        [GIT_BIN, "-C", str(repo_root), *args],
        check=False,
        capture_output=True,
        text=True,
    )
    if completed.returncode != 0:
        stderr = completed.stderr.strip()
        cmd = " ".join(args)
        raise RuntimeError(stderr or f"git failed: {cmd}")
    return completed.stdout


def _get_repo_root() -> Path:
    completed = subprocess.run(  # noqa: S603
        [GIT_BIN, "rev-parse", "--show-toplevel"],
        check=False,
        capture_output=True,
        text=True,
    )
    if completed.returncode != 0:
        raise RuntimeError(completed.stderr.strip() or "git rev-parse failed")
    return Path(completed.stdout.strip())


def _parse_max_loc() -> tuple[int | None, str | None]:
    max_loc_env: Final[str] = os.environ.get("MAX_LOC", "500")
    try:
        max_loc = int(max_loc_env)
    except ValueError:
        return None, f"error: MAX_LOC must be an integer (got {max_loc_env!r})"
    if max_loc < 0:
        return None, f"error: MAX_LOC must be >= 0 (got {max_loc})"
    return max_loc, None


def _resolve_targets(*, repo_root: Path, raw_targets: list[str]) -> tuple[list[Path] | None, str | None]:
    targets: list[Path] = []
    for raw in raw_targets:
        abs_target = Path(raw).resolve()
        if not abs_target.exists():
            return None, f"error: target path does not exist: {raw}"
        try:
            _ = abs_target.relative_to(repo_root)
        except ValueError:
            return None, f"error: {abs_target} is not inside {repo_root}"
        targets.append(abs_target)
    return targets, None


def _rel_prefixes(*, repo_root: Path, targets: list[Path]) -> list[str]:
    prefixes: list[str] = []
    for target in targets:
        rel = target.relative_to(repo_root)
        rel_str = rel.as_posix()
        prefixes.append(rel_str or ".")
    if not prefixes:
        return ["."]
    if any(p == "." for p in prefixes):
        return ["."]
    return prefixes


def _list_files_full(repo_root: Path) -> list[str]:
    stdout = _run_git(repo_root=repo_root, args=["ls-files"])
    return [line for line in stdout.splitlines() if line]


def _list_files_changed(repo_root: Path) -> list[str]:
    candidates: set[str] = set()
    for args in (
        ["diff", "--name-only", "--diff-filter=ACMRTUXB"],
        ["diff", "--name-only", "--cached", "--diff-filter=ACMRTUXB"],
        ["ls-files", "--others", "--exclude-standard"],
    ):
        stdout = _run_git(repo_root=repo_root, args=args)
        for line in stdout.splitlines():
            path = line.strip()
            if path:
                candidates.add(path)
    return sorted(candidates)


def _is_under_prefixes(*, rel_path: str, prefixes: list[str]) -> bool:
    if "." in prefixes:
        return True
    return any(rel_path == prefix or rel_path.startswith(f"{prefix}/") for prefix in prefixes)


def _is_excluded_by_defaults(rel_path: str) -> bool:
    rel = f"/{rel_path}/"
    for banned in ("/vendor/", "/migrations/", "/.venv/", "/__pycache__/"):
        if banned in rel:
            return True
    return False


def _is_excluded_by_user(rel_path: str, excludes: list[str]) -> bool:
    return any(fnmatch(rel_path, pattern) for pattern in excludes)


def _language_allows(*, rel_path: str, language: LanguageMode) -> bool:
    if language == "go":
        return rel_path.endswith(".go")
    if language == "py":
        return rel_path.endswith(".py")
    return rel_path.endswith(".go") or rel_path.endswith(".py")


def _iter_head_lines(*, path: Path, max_lines: int) -> Iterator[str]:
    try:
        with path.open("r", encoding="utf-8", errors="replace") as f:
            count = 0
            for line in f:
                yield line.rstrip("\n")
                count += 1
                if count >= max_lines:
                    return
    except OSError:
        return


def _is_generated(path: Path) -> bool:
    prefixes = ("// Code generated", "# Code generated")
    for line in _iter_head_lines(path=path, max_lines=50):
        stripped = line.strip()
        if stripped.startswith(prefixes):
            return True
        if "DO NOT EDIT" in stripped:
            return True
    return False


def _line_count(path: Path) -> int:
    with path.open("rb") as f:
        return sum(1 for _ in f)


def _iter_checked_files(*, repo_root: Path, cfg: Config) -> Iterable[str]:
    prefixes = _rel_prefixes(repo_root=repo_root, targets=cfg.targets)
    files = _list_files_full(repo_root=repo_root) if cfg.mode == "full" else _list_files_changed(repo_root=repo_root)

    for rel_path in files:
        if not _is_under_prefixes(rel_path=rel_path, prefixes=prefixes):
            continue
        if not _language_allows(rel_path=rel_path, language=cfg.language):
            continue
        if _is_excluded_by_defaults(rel_path):
            continue
        if _is_excluded_by_user(rel_path, cfg.excludes):
            continue
        yield rel_path


def _check(*, repo_root: Path, cfg: Config) -> tuple[bool, int]:
    failed = False
    checked = 0

    for rel_path in _iter_checked_files(repo_root=repo_root, cfg=cfg):
        file_path = repo_root / rel_path
        if not file_path.is_file():
            continue
        if _is_generated(file_path):
            continue

        checked += 1
        lines = _line_count(file_path)
        if lines > cfg.max_loc:
            _eprint(f"error: {rel_path} has {lines} lines (max {cfg.max_loc})")
            failed = True

    return (not failed), checked


def main(argv: list[str]) -> int:
    parser = argparse.ArgumentParser(prog="loc_check.py")
    parser.add_argument(
        "--mode",
        choices=("full", "changed"),
        default="full",
        help="full: scan all tracked files; changed: scan only unstaged/staged/untracked files",
    )
    parser.add_argument(
        "--lang",
        choices=("go", "py", "both"),
        default="both",
        help="which file types to check",
    )
    parser.add_argument(
        "--exclude",
        action="append",
        default=[],
        help="repo-relative glob to exclude (repeatable), e.g. 'common/**' or '**/generated/**'",
    )
    parser.add_argument(
        "paths",
        nargs="*",
        default=["."],
        help="directories/files to scan (default: current directory)",
    )
    args = parser.parse_args(argv)

    max_loc, max_loc_err = _parse_max_loc()
    if max_loc is None:
        _eprint(max_loc_err or "error: invalid MAX_LOC")
        return _EXIT_USAGE_ERROR

    try:
        repo_root = _get_repo_root()
    except RuntimeError as exc:
        _eprint(f"error: {exc}")
        return _EXIT_USAGE_ERROR

    targets, targets_err = _resolve_targets(repo_root=repo_root, raw_targets=list(args.paths))
    if targets is None:
        _eprint(targets_err or "error: invalid target paths")
        return _EXIT_USAGE_ERROR

    cfg = Config(
        mode=str(args.mode),  # type: ignore[arg-type]
        language=str(args.lang),  # type: ignore[arg-type]
        targets=targets,
        excludes=list(args.exclude),
        max_loc=max_loc,
    )

    ok, checked = _check(repo_root=repo_root, cfg=cfg)
    if not ok:
        _eprint("LOC check failed.")
        return 1
    _oprint(f"LOC check passed (mode={cfg.mode}; checked {checked} files; max {cfg.max_loc} lines per file).")
    return 0


if __name__ == "__main__":
    raise SystemExit(main(sys.argv[1:]))
