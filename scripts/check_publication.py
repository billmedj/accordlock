#!/usr/bin/env python3
"""Fail-closed publication checks for the AccordLock public monorepo."""

from __future__ import annotations

from dataclasses import dataclass
import os
from pathlib import Path, PurePosixPath
import re
import subprocess
import sys
from typing import Iterable


ROOT = Path(__file__).resolve().parents[1]
HEX40 = re.compile(r"^[0-9a-f]{40}$")
MARKDOWN_LINK = re.compile(r"(?<!!)\[[^\]]*\]\(([^)]+)\)")
USES_LINE = re.compile(r"^\s*-?\s*uses:\s*([^\s#]+)", re.MULTILINE)

REQUIRED_PATHS = (
    ".github/ISSUE_TEMPLATE/bug.yml",
    ".github/ISSUE_TEMPLATE/config.yml",
    ".github/ISSUE_TEMPLATE/feature.yml",
    ".github/RELEASE_CHECKLIST.md",
    ".github/dependabot.yml",
    ".github/pull_request_template.md",
    ".github/workflows/ci.yml",
    ".github/workflows/reproducibility.yml",
    "assurance/claims.yaml",
    "assurance/verify.py",
    "demos/README.md",
    "docs/ARCHITECTURE.md",
    "docs/LIMITATIONS.md",
    "docs/PRODUCT_STATUS.md",
    "docs/THREAT_MODEL.md",
    "LICENSE",
    "NOTICE",
    "README.md",
    "SECURITY.md",
    "scripts/check_lean_sources.py",
    "scripts/check_source_provenance.py",
    "scripts/test_all.py",
    "SOURCE_PROVENANCE.json",
)

ROOT_AUTHORED_PREFIXES = (
    ".github/",
    "assurance/",
    "demos/",
    "docs/",
    "scripts/",
    "tests/",
)

ROOT_AUTHORED_FILES = {
    ".gitignore",
    "CHANGELOG.md",
    "CITATION.cff",
    "CODE_OF_CONDUCT.md",
    "CONTRIBUTING.md",
    "GOVERNANCE.md",
    "LICENSE",
    "NOTICE",
    "README.md",
    "SECURITY.md",
    "SOURCE_PROVENANCE.json",
    "SUPPORT.md",
    "THIRD_PARTY_NOTICES.md",
    "TRADEMARKS.md",
}

TEXT_SUFFIXES = {
    ".cff",
    ".css",
    ".html",
    ".json",
    ".md",
    ".ps1",
    ".py",
    ".rs",
    ".sh",
    ".toml",
    ".ts",
    ".tsx",
    ".txt",
    ".yaml",
    ".yml",
}

GENERATED_PARTS = {
    ".demo-runs",
    ".lake",
    ".pytest_cache",
    "__pycache__",
    "node_modules",
    "target",
}


@dataclass(frozen=True)
class Finding:
    check: str
    detail: str


def _git(*arguments: str) -> list[str]:
    result = subprocess.run(
        ["git", "-C", str(ROOT), *arguments],
        check=False,
        capture_output=True,
        text=True,
        timeout=30,
    )
    if result.returncode != 0:
        diagnostic = result.stderr.strip() or result.stdout.strip() or "no diagnostic"
        raise RuntimeError(f"git {' '.join(arguments)} failed: {diagnostic}")
    return [line for line in result.stdout.splitlines() if line]


def _candidate_files() -> list[str]:
    paths = _git("ls-files", "--cached", "--others", "--exclude-standard")
    return sorted({PurePosixPath(path).as_posix() for path in paths})


def _root_authored(path: str) -> bool:
    return path in ROOT_AUTHORED_FILES or path.startswith(ROOT_AUTHORED_PREFIXES)


def _read_text(path: Path) -> str:
    if path.stat().st_size > 4 * 1024 * 1024:
        raise ValueError("text file exceeds the 4 MiB publication-scan limit")
    return path.read_text(encoding="utf-8")


def check_required_paths() -> list[Finding]:
    return [
        Finding("required-path", path)
        for path in REQUIRED_PATHS
        if not (ROOT / path).is_file()
    ]


def check_generated_files(paths: Iterable[str]) -> list[Finding]:
    findings: list[Finding] = []
    for path in paths:
        parts = PurePosixPath(path).parts
        if any(part in GENERATED_PARTS for part in parts):
            findings.append(Finding("generated-file", path))
        if path.startswith("demos/artifacts/") and not path.endswith("/.gitkeep"):
            findings.append(Finding("generated-demo-artifact", path))
        if path.endswith((".exe", ".msi", ".dmg", ".app", ".deb", ".rpm")):
            findings.append(Finding("packaged-binary", path))
    return findings


def _sensitive_patterns() -> tuple[tuple[str, re.Pattern[str]], ...]:
    # Fragments keep the scanner from matching its own policy source.
    private_terms = (
        "C" + "RCS",
        "C" + "VT",
        "binding" + r"[ _-]?gates?",
        "semantim" + r"(?:eter|etre|etry|etrie)",
        "Taf" + "sir",
        "Qur" + "an",
    )
    return (
        (
            "private-research-term",
            re.compile(r"(?i)(?:" + "|".join(private_terms) + r")"),
        ),
        (
            "personal-home-path",
            re.compile(
                r"(?i)(?:[a-z]:[\\/]Use"
                + r"rs[\\/][^\\/\s]+|/Use"
                + r"rs/[^/\s]+|/ho"
                + r"me/[^/\s]+)"
            ),
        ),
        (
            "github-token",
            re.compile(r"(?:gh" + r"[opsu]_[A-Za-z0-9]{30,}|github_pat_[A-Za-z0-9_]{20,})"),
        ),
        (
            "aws-access-key",
            re.compile(r"(?:AKIA|ASIA)[A-Z0-9]{16}"),
        ),
        (
            "private-key-material",
            re.compile(r"-----BEGIN (?:RSA |EC |OPENSSH )?PRIVATE KEY-----"),
        ),
    )


def check_root_text(paths: Iterable[str]) -> list[Finding]:
    findings: list[Finding] = []
    patterns = _sensitive_patterns()
    for relative in paths:
        path = ROOT / relative
        if not _root_authored(relative) or path.suffix.lower() not in TEXT_SUFFIXES:
            continue
        try:
            text = _read_text(path)
        except (OSError, UnicodeError, ValueError) as error:
            findings.append(Finding("text-read", f"{relative}: {error}"))
            continue
        for label, pattern in patterns:
            match = pattern.search(text)
            if match:
                line = text.count("\n", 0, match.start()) + 1
                findings.append(Finding(label, f"{relative}:{line}"))
    return findings


def _link_target(raw: str) -> str:
    target = raw.strip()
    if target.startswith("<") and target.endswith(">"):
        target = target[1:-1]
    if " " in target and not target.startswith(("http://", "https://")):
        target = target.split(" ", 1)[0]
    return target


def check_markdown_links(paths: Iterable[str]) -> list[Finding]:
    findings: list[Finding] = []
    for relative in paths:
        if not _root_authored(relative) or not relative.endswith(".md"):
            continue
        source = ROOT / relative
        try:
            text = _read_text(source)
        except (OSError, UnicodeError, ValueError):
            continue
        for raw in MARKDOWN_LINK.findall(text):
            target = _link_target(raw)
            if not target or target.startswith(("#", "http://", "https://", "mailto:")):
                continue
            file_part = target.split("#", 1)[0]
            if not file_part:
                continue
            candidate = (source.parent / file_part).resolve()
            try:
                candidate.relative_to(ROOT.resolve())
            except ValueError:
                findings.append(Finding("link-outside-repository", f"{relative}: {target}"))
                continue
            if not candidate.exists():
                findings.append(Finding("broken-relative-link", f"{relative}: {target}"))
    return findings


def validate_workflow_text(relative: str, text: str) -> list[Finding]:
    findings: list[Finding] = []
    if re.search(r"(?m)^\s*pull_request_target\s*:", text):
        findings.append(Finding("unsafe-workflow-trigger", relative))
    if re.search(r"(?im)^\s*permissions\s*:\s*write-all\s*$", text):
        findings.append(Finding("write-all-permission", relative))
    if re.search(r"(?im)^\s*contents\s*:\s*write\s*$", text):
        findings.append(Finding("contents-write-permission", relative))
    if re.search(r"(?i)softprops/action-gh-release|gh\s+release\s+create", text):
        findings.append(Finding("release-publication-step", relative))
    for use in USES_LINE.findall(text):
        if use.startswith("./") or use.startswith("docker://"):
            continue
        if "@" not in use:
            findings.append(Finding("unpinned-action", f"{relative}: {use}"))
            continue
        _, reference = use.rsplit("@", 1)
        if not HEX40.fullmatch(reference):
            findings.append(Finding("unpinned-action", f"{relative}: {use}"))
    return findings


def check_root_workflows(paths: Iterable[str]) -> list[Finding]:
    findings: list[Finding] = []
    for relative in paths:
        if not relative.startswith(".github/workflows/") or not relative.endswith((".yml", ".yaml")):
            continue
        try:
            text = _read_text(ROOT / relative)
        except (OSError, UnicodeError, ValueError) as error:
            findings.append(Finding("workflow-read", f"{relative}: {error}"))
            continue
        findings.extend(validate_workflow_text(relative, text))
    return findings


def _run_guard(name: str, command: list[str], cwd: Path) -> list[Finding]:
    environment = os.environ.copy()
    environment["PYTHONDONTWRITEBYTECODE"] = "1"
    result = subprocess.run(
        command,
        cwd=cwd,
        env=environment,
        check=False,
        capture_output=True,
        text=True,
        timeout=180,
    )
    if result.returncode == 0:
        summary = next((line for line in result.stdout.splitlines() if line.strip()), "PASS")
        print(f"PASS {name}: {summary}")
        return []
    diagnostic = (result.stderr.strip() or result.stdout.strip() or "no diagnostic")[-2000:]
    return [Finding(name, diagnostic)]


def main() -> int:
    try:
        candidate = _candidate_files()
    except RuntimeError as error:
        print(f"FAIL repository-state: {error}", file=sys.stderr)
        return 1

    findings: list[Finding] = []
    findings.extend(check_required_paths())
    findings.extend(check_generated_files(candidate))
    findings.extend(check_root_text(candidate))
    findings.extend(check_markdown_links(candidate))
    findings.extend(check_root_workflows(candidate))

    if not findings:
        python = sys.executable
        findings.extend(
            _run_guard(
                "source-provenance",
                [python, "scripts/check_source_provenance.py"],
                ROOT,
            )
        )
        findings.extend(
            _run_guard(
                "runtime-publication",
                [python, "scripts/validate_repository.py"],
                ROOT / "runtime",
            )
        )
        findings.extend(
            _run_guard(
                "desktop-publication",
                [python, "scripts/check_accordlock_publication.py"],
                ROOT / "desktop",
            )
        )
        findings.extend(
            _run_guard(
                "assurance-map",
                [python, "assurance/verify.py", "--root", "runtime", "--json"],
                ROOT,
            )
        )
        findings.extend(
            _run_guard(
                "lean-source-policy",
                [python, "scripts/check_lean_sources.py"],
                ROOT,
            )
        )

    if findings:
        for finding in findings:
            print(f"FAIL {finding.check}: {finding.detail}", file=sys.stderr)
        print(f"FAIL publication_gate findings={len(findings)}", file=sys.stderr)
        return 1

    root_files = sum(1 for path in candidate if _root_authored(path))
    workflows = sum(1 for path in candidate if path.startswith(".github/workflows/"))
    print(
        "PASS publication_gate "
        f"candidate_files={len(candidate)} root_authored_files={root_files} "
        f"root_workflows={workflows}"
    )
    print("BOUNDARY publication checks validate source hygiene and repository policy, not production safety")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
