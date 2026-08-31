#!/usr/bin/env python3
"""Fail closed when upstream release/install surfaces reappear in AccordLock."""

from __future__ import annotations

import re
import subprocess
import sys
from pathlib import Path


ROOT = Path(__file__).resolve().parents[1]

ACTIVE_WORKFLOWS = (
    ".github/workflows/accordlock-publication-guard.yml",
    ".github/workflows/accordlock-technical-preview-ci.yml",
)

QUARANTINED_WORKFLOWS = (
    ".github/workflows/release.yml",
    ".github/workflows/canary.yml",
    ".github/workflows/code-review.yml",
    ".github/workflows/bundle-desktop-linux.yml",
    ".github/workflows/bundle-macos.yml",
    ".github/workflows/bundle-windows.yml",
    ".github/workflows/build-cli.yml",
    ".github/workflows/build-cli-linux.yml",
    ".github/workflows/check-release-pr.yaml",
    ".github/workflows/close-release-pr-on-tag.yaml",
    ".github/workflows/create-release-branch.yaml",
    ".github/workflows/create-version-bump-pr.yaml",
    ".github/workflows/docs-update-cli-ref.yml",
    ".github/workflows/goose-release-notes.yml",
    ".github/workflows/maven-sdk.yml",
    ".github/workflows/minor-release.yaml",
    ".github/workflows/patch-release.yaml",
    ".github/workflows/publish-ask-ai-bot.yml",
    ".github/workflows/publish-docker.yml",
    ".github/workflows/publish-npm.yml",
    ".github/workflows/python-sdk-wheels.yml",
    ".github/workflows/pr-smoke-test.yml",
    ".github/workflows/release-branches.yml",
    ".github/workflows/update-release-pr.yaml",
    ".github/workflows/build-notify.yml",
    ".github/workflows/cargo-deny.yml",
    ".github/workflows/cargo-machete.yml",
    ".github/workflows/ci.yml",
    ".github/workflows/dependabot-auto-merge.yml",
    ".github/workflows/deploy-docs-and-extensions.yml",
    ".github/workflows/goose-issue-solver.yml",
    ".github/workflows/goose-pr-reviewer.yml",
    ".github/workflows/pr-website-preview.yml",
    ".github/workflows/quarantine.yml",
    ".github/workflows/recipe-security-scanner.yml",
    ".github/workflows/scorecard.yml",
    ".github/workflows/stale.yml",
    ".github/workflows/take.yml",
    ".github/workflows/update-health-dashboard.yml",
)

OWNED_TEXT_EXACT = {
    "README.md",
    "scripts/build-windows.ps1",
    "ui/desktop/README.md",
    "ui/desktop/ACCORDLOCK_DISTRIBUTION.md",
    "ui/desktop/package.json",
    "ui/desktop/scripts/verify-accordlock-backend.js",
}

OWNED_TEXT_PREFIXES = (
    "crates/goose/src/agents/accordlock_",
    "ui/desktop/src/accordlock",
    "ui/desktop/src/components/accordlock/",
    "ui/desktop/src/components/onboarding/",
    "ui/desktop/src/components/settings/app/TerminalProgramsSettings",
    "ui/desktop/src/i18n/messages/",
    "ui/desktop/src/i18n/compiled/",
)

BANNED_OWNED_TERMS = (
    ("obsolete research acronym", re.compile(r"(?<![a-z0-9])c" r"rcs(?![a-z0-9])", re.IGNORECASE)),
    ("obsolete gate term", re.compile(r"(?<![a-z0-9])bind" r"ing[-_ ]+gates?(?![a-z0-9])", re.IGNORECASE)),
    ("obsolete metric name", re.compile(r"(?:(?<![a-z0-9])r" r"ho(?![a-z0-9])|\u03c1)", re.IGNORECASE)),
    ("semantic", re.compile(r"(?<![a-z0-9])semantic(?:s|ally|[_ -][a-z]+)?", re.IGNORECASE)),
    ("mission", re.compile(r"(?<![a-z0-9])mission(?:s|[_ -][a-z]+)?", re.IGNORECASE)),
    ("governance", re.compile(r"\bgovern(?:ed|ance|ing)?\b", re.IGNORECASE)),
    ("permit token", re.compile(r"\b(?:agenttoolpermit|permit[_ -](?:jti|hash))\b", re.IGNORECASE)),
    ("gate decision", re.compile(r"\b(?:gatedecision|gateoutcome)\b", re.IGNORECASE)),
    ("legacy approval field", re.compile(r"\breview_context(?:_hash)?\b", re.IGNORECASE)),
    # Versioned hash domains are durable protocol identifiers, not product copy.
    # Retired HTTP routes remain forbidden, while signed v1 records stay readable.
    ("legacy v1 HTTP route", re.compile(r"/api/v1/", re.IGNORECASE)),
)

PERSONAL_PATH_PATTERNS = (
    re.compile(
        r"[A-Za-z]:[\\/]+Users[\\/]+(?!example\b|user\b|goose\b)[^\\/\s]+",
        re.IGNORECASE,
    ),
    re.compile(r"/Users/(?!example\b|user\b)[^/\s]+", re.IGNORECASE),
    re.compile(
        r"/home/(?!example\b|user\b|goose\b|runner\b|ubuntu\b|node\b|vscode\b|accordlock\b|scanner\b)[^/\s]+",
        re.IGNORECASE,
    ),
)

SECRET_PATTERNS = (
    re.compile(r"\bAKIA[0-9A-Z]{16}\b"),
    re.compile(r"\bgh[pousr]_[A-Za-z0-9]{36,}\b"),
    re.compile(r"\bsk-(?:proj-)?[A-Za-z0-9_-]{20,}\b"),
    re.compile(r"-----BEGIN (?:RSA |EC |OPENSSH )?PRIVATE KEY-----"),
)

PUBLIC_INSTALL_SURFACES = (
    "README.md",
    "BUILDING_DOCKER.md",
    "BUILDING_LINUX.md",
    "Dockerfile",
    "download_cli.sh",
    "download_cli.ps1",
    "scripts/pre-release.sh",
    "recipe-scanner/Dockerfile",
    "recipe-scanner/scan-recipe.sh",
)

HARDENED_BUILD_SURFACES = (
    "Dockerfile",
)

BANNED_INSTALL_PATTERNS = (
    re.compile(r"github\.com/aaif-goose/goose/releases", re.IGNORECASE),
    re.compile(r"api\.github\.com/repos/aaif-goose/goose/releases", re.IGNORECASE),
    re.compile(
        r"raw\.githubusercontent\.com/aaif-goose/goose/main/download_cli",
        re.IGNORECASE,
    ),
    re.compile(r"\bblock-goose(?:-cli)?\b", re.IGNORECASE),
    re.compile(r"ghcr\.io/aaif-goose/goose", re.IGNORECASE),
    re.compile(r"goose-docs\.ai/docs/getting-started/installation", re.IGNORECASE),
)

BANNED_UPLOAD_PATTERNS = (
    "actions/upload-artifact",
    "softprops/action-gh-release",
    "gh release create",
    "gh release upload",
    "npm publish",
    "docker push",
)


def read(relative_path: str) -> str:
    path = ROOT / relative_path
    if not path.is_file():
        raise AssertionError(f"required publication surface is missing: {relative_path}")
    return path.read_text(encoding="utf-8")


def git_files(root: Path, *arguments: str) -> tuple[str, ...]:
    result = subprocess.run(
        ["git", "ls-files", "-z", *arguments],
        cwd=root,
        check=True,
        capture_output=True,
    )
    return tuple(
        sorted(
            path.decode("utf-8", errors="strict").replace("\\", "/")
            for path in result.stdout.split(b"\0")
            if path
        )
    )


def repository_file_sets(root: Path = ROOT) -> tuple[set[str], set[str]]:
    """Return tracked and non-ignored untracked files from a Git worktree."""
    tracked = set(git_files(root, "--cached"))
    untracked = set(git_files(root, "--others", "--exclude-standard"))
    return tracked, untracked


def is_owned_text(relative_path: str) -> bool:
    return (
        relative_path in OWNED_TEXT_EXACT
        or relative_path in PUBLIC_INSTALL_SURFACES
        or relative_path.startswith(OWNED_TEXT_PREFIXES)
    )


def check_repository_hygiene(errors: list[str], root: Path = ROOT) -> None:
    tracked, untracked = repository_file_sets(root)
    files = tuple(
        sorted(path for path in tracked | untracked if (root / path).is_file())
    )
    for relative_path in files:
        path = Path(relative_path)
        lower_path = relative_path.lower()

        if relative_path in untracked:
            errors.append(
                f"{relative_path}: untracked publication input; stage it or ignore it explicitly"
            )

        if path.name == ".env":
            errors.append(f"{relative_path}: tracked or visible .env files are forbidden")
        if lower_path.startswith("ui/desktop/src/i18n/messages/") and path.suffix == ".json":
            if path.name != "en.json":
                errors.append(f"{relative_path}: non-English message catalog is forbidden")
        if lower_path.startswith("ui/desktop/src/i18n/compiled/"):
            errors.append(f"{relative_path}: generated message catalogs must not be published")
        if any(
            marker in lower_path
            for marker in (
                "/.accordlock-dev-runtime/",
                "/.accordlock-dev-user-data/",
                "ui/desktop/src/bin/goose",
                "ui/desktop/src/bin/accordlock-build.json",
                "ui/desktop/src/bin/accordlock-runtime-build.json",
                "ui/desktop/src/bin/accordlock-preflight-runner-build.json",
                "ui/desktop/src/bin/accordlock-agent-runtime",
                "ui/desktop/src/bin/accordlock-preflight-runner",
            )
        ):
            errors.append(f"{relative_path}: local runtime or build artifact is forbidden")

        if not is_owned_text(relative_path):
            continue
        try:
            content = (root / relative_path).read_text(encoding="utf-8")
        except UnicodeDecodeError:
            continue
        for label, pattern in BANNED_OWNED_TERMS:
            match = pattern.search(content)
            if match:
                line = content.count("\n", 0, match.start()) + 1
                errors.append(f"{relative_path}:{line}: obsolete AccordLock term: {label}")
        accented = re.search(r"[À-ÖØ-öø-ÿŒœ]", content)
        if accented:
            line = content.count("\n", 0, accented.start()) + 1
            errors.append(f"{relative_path}:{line}: non-English accented text is forbidden")
        for pattern in PERSONAL_PATH_PATTERNS:
            match = pattern.search(content)
            if match:
                line = content.count("\n", 0, match.start()) + 1
                errors.append(f"{relative_path}:{line}: personal absolute path is forbidden")
        for pattern in SECRET_PATTERNS:
            match = pattern.search(content)
            if match:
                line = content.count("\n", 0, match.start()) + 1
                errors.append(f"{relative_path}:{line}: possible committed secret is forbidden")


def workflow_triggers(content: str) -> set[str]:
    """Return the top-level events nested under the workflow's ``on`` key."""
    lines = content.splitlines()
    for index, line in enumerate(lines):
        if line == "on:":
            triggers: set[str] = set()
            for nested in lines[index + 1 :]:
                if nested and not nested[0].isspace():
                    break
                match = re.match(r"^ {2}([a-zA-Z_][a-zA-Z0-9_]*):", nested)
                if match:
                    triggers.add(match.group(1))
            return triggers
        if re.match(r"^on:\s*\S", line):
            raise AssertionError("inline workflow triggers are forbidden")
    raise AssertionError("workflow is missing an on block")


def artifact_upload_blocks(content: str) -> list[str]:
    """Extract upload-artifact steps so their paths can be checked explicitly."""
    lines = content.splitlines()
    blocks: list[str] = []
    for index, line in enumerate(lines):
        if "actions/upload-artifact" not in line.lower():
            continue
        indent = len(line) - len(line.lstrip())
        block = [line]
        for nested in lines[index + 1 :]:
            nested_indent = len(nested) - len(nested.lstrip())
            if nested.lstrip().startswith("- ") and nested_indent <= indent:
                break
            block.append(nested)
        blocks.append("\n".join(block))
    return blocks


def check_artifact_boundaries(errors: list[str]) -> None:
    workflow_root = ROOT / ".github" / "workflows"
    for path in sorted((*workflow_root.glob("*.yml"), *workflow_root.glob("*.yaml"))):
        relative_path = path.relative_to(ROOT).as_posix()
        content = path.read_text(encoding="utf-8")
        lower = content.lower()
        if re.search(r"oidc[-_]?token", lower):
            errors.append(f"{relative_path}: persisting an OIDC token is forbidden")
        for block in artifact_upload_blocks(content):
            lower_block = block.lower()
            if "/tmp/" in lower_block:
                errors.append(f"{relative_path}: uploading an absolute temp path is forbidden")
            if any(
                marker in lower_block
                for marker in (
                    "name: goose-binary",
                    "target/debug/",
                    "target/release/",
                    ".appimage",
                    ".deb",
                    ".dmg",
                    ".exe",
                    ".msi",
                    ".rpm",
                    ".tar.",
                    ".zip",
                )
            ):
                errors.append(f"{relative_path}: uploading executable/package artifacts is forbidden")


def check_workflows(errors: list[str]) -> None:
    workflow_root = ROOT / ".github" / "workflows"
    actual_workflows = {
        path.relative_to(ROOT).as_posix()
        for path in (*workflow_root.glob("*.yml"), *workflow_root.glob("*.yaml"))
    }
    classified_workflows = set(ACTIVE_WORKFLOWS) | set(QUARANTINED_WORKFLOWS)
    for relative_path in sorted(actual_workflows - classified_workflows):
        errors.append(f"{relative_path}: workflow is not explicitly classified")
    for relative_path in sorted(classified_workflows - actual_workflows):
        errors.append(f"{relative_path}: classified workflow is missing")

    for relative_path in ACTIVE_WORKFLOWS:
        content = read(relative_path)
        lower = content.lower()
        if "permissions:\n  contents: read" not in content:
            errors.append(f"{relative_path}: active workflow must have read-only permissions")
        if "secrets." in lower:
            errors.append(f"{relative_path}: active workflow may not consume repository secrets")
        if re.search(r"^\s+[a-zA-Z_-]+:\s*write\s*$", content, re.MULTILINE):
            errors.append(f"{relative_path}: active workflow has write permission")
        for marker in BANNED_UPLOAD_PATTERNS:
            if marker in lower:
                errors.append(f"{relative_path}: active workflow may not publish: {marker}")

    allowed_triggers = {"workflow_call", "workflow_dispatch"}
    for relative_path in QUARANTINED_WORKFLOWS:
        content = read(relative_path)
        lower = content.lower()
        if 'accordlock_publication_disabled: "true"' not in lower:
            errors.append(f"{relative_path}: missing publication-disabled marker")
        if "accordlock-distribution" not in content:
            errors.append(f"{relative_path}: missing unique hardened profile guard")
        if "workflow_dispatch:" not in content:
            errors.append(f"{relative_path}: must remain manual")
        try:
            forbidden_triggers = workflow_triggers(content) - allowed_triggers
        except AssertionError as error:
            errors.append(f"{relative_path}: {error}")
        else:
            if forbidden_triggers:
                errors.append(
                    f"{relative_path}: forbidden trigger(s): "
                    f"{', '.join(sorted(forbidden_triggers))}"
                )
        if re.search(r"^\s+[a-zA-Z_-]+:\s*write\s*$", content, re.MULTILINE):
            errors.append(f"{relative_path}: write permission is forbidden")
        if 'test "$PUBLICATION_PROFILE" = "accordlock-distribution"' not in content and (
            '$env:PUBLICATION_PROFILE -ne "accordlock-distribution"' not in content
        ):
            errors.append(f"{relative_path}: hardened profile is not checked at runtime")
        if "exit 1" not in content and "throw \"" not in lower:
            errors.append(f"{relative_path}: quarantine must terminate fail-closed")
        for marker in BANNED_UPLOAD_PATTERNS:
            if marker in lower:
                errors.append(f"{relative_path}: upload command/action is forbidden: {marker}")


def check_public_surfaces(errors: list[str]) -> None:
    for relative_path in PUBLIC_INSTALL_SURFACES:
        content = read(relative_path)
        for pattern in BANNED_INSTALL_PATTERNS:
            if pattern.search(content):
                errors.append(
                    f"{relative_path}: inherited upstream installer/download reference is forbidden"
                )

    for relative_path in HARDENED_BUILD_SURFACES:
        content = read(relative_path)
        for required in (
            "--locked",
            "--no-default-features",
            "accordlock-distribution,rustls-tls,system-keyring",
        ):
            if required not in content:
                errors.append(
                    f"{relative_path}: hardened source build is missing {required}"
                )

    readme = read("README.md").lower()
    for required in (
        "source alpha",
        "no public signed installer",
        "--no-default-features",
        "--features accordlock-distribution",
        "apache-2.0",
        "https://github.com/aaif-goose/goose",
    ):
        if required not in readme:
            errors.append(f"README.md: missing required source/publication statement: {required}")

    shell_installer = read("download_cli.sh")
    if "exit 64" not in shell_installer or "curl " in shell_installer or "wget " in shell_installer:
        errors.append("download_cli.sh: must be a non-downloading fail-closed stub")

    powershell_installer = read("download_cli.ps1")
    if "throw" not in powershell_installer.lower() or "invoke-webrequest" in powershell_installer.lower():
        errors.append("download_cli.ps1: must be a non-downloading fail-closed stub")

    recipe_scanner = read("recipe-scanner/scan-recipe.sh")
    if "does not download or install agent binaries" not in recipe_scanner or (
        "exit 64" not in recipe_scanner
    ):
        errors.append("recipe-scanner/scan-recipe.sh: missing-binary path must fail closed")

    update_source = read("crates/goose-cli/src/commands/update.rs")
    accordlock_gate = '#[cfg(feature = "accordlock-distribution")]'
    upstream_gate = 'not(feature = "accordlock-distribution")'
    upstream_release = "https://github.com/aaif-goose/goose/releases/download/"
    for required in (
        accordlock_gate,
        upstream_gate,
        "no approved update channel",
        "test_accordlock_update_is_unconditionally_unavailable",
    ):
        if required not in update_source:
            errors.append(f"update.rs: missing AccordLock update boundary: {required}")
    if upstream_release not in update_source:
        errors.append("update.rs: upstream-compatible update implementation was removed")
    elif update_source.find(accordlock_gate) > update_source.find(upstream_release):
        errors.append("update.rs: AccordLock fail-closed gate must precede upstream resolution")


def main() -> int:
    errors: list[str] = []
    try:
        check_workflows(errors)
        check_artifact_boundaries(errors)
        check_public_surfaces(errors)
        check_repository_hygiene(errors)
    except (OSError, UnicodeError, AssertionError, subprocess.SubprocessError) as error:
        errors.append(str(error))

    if errors:
        print("AccordLock publication guard: FAIL", file=sys.stderr)
        for error in errors:
            print(f"- {error}", file=sys.stderr)
        return 1

    print(
        "AccordLock publication guard: PASS "
        f"({len(ACTIVE_WORKFLOWS) + len(QUARANTINED_WORKFLOWS)} workflows: "
        f"{len(ACTIVE_WORKFLOWS)} active, {len(QUARANTINED_WORKFLOWS)} quarantined; "
        f"{len(PUBLIC_INSTALL_SURFACES)} public surfaces)"
    )
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
