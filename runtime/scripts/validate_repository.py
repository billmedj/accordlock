#!/usr/bin/env python3
"""Fail-closed, dependency-free validation of AccordLock repository contracts.

This checks syntax and cross-file consistency.  It does not execute the
conformance scenarios and must not be reported as a conformance result.
"""

from __future__ import annotations

import argparse
import json
import re
import subprocess
import sys
import unicodedata
from pathlib import Path
from typing import Any
from urllib.parse import unquote


PUBLICATION_REQUIRED_FILES = (
    "README.md",
    "LICENSE",
    "SECURITY.md",
    "CONTRIBUTING.md",
    "CODE_OF_CONDUCT.md",
    "SUPPORT.md",
    "TRADEMARKS.md",
)
LEGACY_BRAND_BYTES = (b"sig" + b"net").lower()
MARKDOWN_LINK_PATTERN = re.compile(
    r"!?\[[^\]\r\n]*\]\((?P<target><[^>\r\n]+>|[^)\r\n]+)\)"
)
MARKDOWN_REFERENCE_PATTERN = re.compile(
    r"^\s{0,3}\[[^\]\r\n]+\]:\s*(?P<target><[^>\r\n]+>|\S+)",
    re.M,
)
POSTGRES_IDENTIFIER_PATTERN = re.compile(r"\baccordlock_[A-Za-z0-9_]+\b")
POSTGRES_IDENTIFIER_MAX_BYTES = 63

# Publication checks intentionally assemble retired codenames from fragments so
# the validator does not reintroduce the strings it is designed to reject.
OBSOLETE_TERMINOLOGY_PATTERNS = (
    (
        "legacy policy-evaluation codename",
        re.compile(
            r"(?<![A-Za-z0-9])" + "cr" + "cs" + r"(?![A-Za-z0-9])",
            re.IGNORECASE,
        ),
    ),
    (
        "legacy policy-check phrase",
        re.compile("binding" + r"[ _-]?" + "gates?", re.IGNORECASE),
    ),
    (
        "legacy normalized-score name",
        re.compile(
            r"(?:(?<![A-Za-z0-9])" + "r" + "ho" + r"(?![A-Za-z0-9])|\u03c1)",
            re.IGNORECASE,
        ),
    ),
    (
        "legacy semantic-measurement terminology",
        re.compile(
            "seman" + r"tic[ _-]?(?:meter|transfer(?:[ _-]?chain)?)",
            re.IGNORECASE,
        ),
    ),
    (
        "legacy task terminology",
        re.compile(
            r"(?<![A-Za-z0-9])" + "mis" + "sions?" + r"(?![A-Za-z0-9])",
            re.IGNORECASE,
        ),
    ),
    (
        "legacy execution-authorization terminology",
        re.compile(
            r"(?:(?<![A-Za-z0-9])" + "per" + "mits?" + r"(?![A-Za-z0-9])|"
            + "Action" + "Per" + "mit" + r"|" + "per" + "mit"
            + r"[_-](?:jti|hash))",
            re.IGNORECASE,
        ),
    ),
    (
        "legacy execution-state terminology",
        re.compile("effect" + r"[ _-]?" + "state", re.IGNORECASE),
    ),
    (
        "unrelated research provenance",
        re.compile(
            r"(?:\b" + "when" + "ce" + r"\b|\b" + "zen" + "odo" + r"\b|\b"
            + "Qur" + "an" + r"\b)",
            re.IGNORECASE,
        ),
    ),
)

NON_ENGLISH_PRODUCT_COPY_PATTERN = re.compile(
    r"\b(?:"
    + "bien" + "venue"
    + "|" + "nou" + "velle"
    + "|" + "histo" + "rique"
    + "|" + "para" + "metres"
    + "|" + "auto" + "riser"
    + "|" + "refu" + "ser"
    + "|" + "approu" + "ver"
    + "|" + "annu" + "ler"
    + "|" + "conne" + "xion"
    + "|" + "deploie" + "ment"
    + "|" + "secu" + "rite"
    + "|" + "poli" + "tique"
    + "|" + "fourni" + "sseur"
    + "|" + "mode" + "le"
    + r")\b",
    re.IGNORECASE,
)

PRIVATE_PATH_PATTERNS = (
    re.compile(r"(?i)\b[A-Z]:[\\/](?:Users|Documents[ ]and[ ]Settings)[\\/]"),
    re.compile(r"(?i)(?<![A-Za-z0-9_.-])/(?:Users|home)/[A-Za-z0-9_.-]+/"),
    re.compile(r"(?i)(?<![A-Za-z0-9_.-])/mnt/[a-z]/Users/[A-Za-z0-9_.-]+/"),
)

RUNTIME_ARTIFACT_NAMES = {".env", ".coverage", "id_rsa", "id_ed25519"}
RUNTIME_ARTIFACT_SUFFIXES = {
    ".db",
    ".key",
    ".log",
    ".p12",
    ".pem",
    ".pid",
    ".pyc",
    ".sock",
    ".sqlite",
    ".sqlite3",
}
RUNTIME_ARTIFACT_DIRECTORIES = {"__pycache__", ".pytest_cache", ".mypy_cache"}
SAFE_ENV_TEMPLATE_NAMES = {".env.example", ".env.sample", ".env.template"}

CREDENTIAL_PATTERNS = (
    ("AWS access key", re.compile(r"\b(?:AKIA|ASIA)[0-9A-Z]{16}\b")),
    ("GitHub token", re.compile(r"\bgh[pousr]_[A-Za-z0-9_]{20,}\b")),
    ("model-provider key", re.compile(r"\bsk-(?:ant-[A-Za-z0-9_-]{20,}|[A-Za-z0-9_-]{32,})\b")),
    ("Google API key", re.compile(r"\bAIza[0-9A-Za-z_-]{35}\b")),
    ("Slack token", re.compile(r"\bxox[baprs]-[0-9A-Za-z-]{20,}\b")),
    (
        "private key block",
        re.compile(r"-----BEGIN (?:RSA |EC |OPENSSH )?PRIVATE KEY-----"),
    ),
)
SAFE_CREDENTIAL_VECTOR_PREFIXES = ("tests/fixtures/", "conformance/")
SAFE_CREDENTIAL_VECTOR_MARKER = "publication-safe-test-vector"

LEGAL_ATTRIBUTION_FILES = {
    "Cargo.toml",
    "CITATION.cff",
    "GOVERNANCE.md",
    "LICENSE",
    "NOTICE",
    "TRADEMARKS.md",
}
LEGAL_AUTHOR_PATTERN = re.compile(r"\b" + "Bilal" + r"\s+" + "Medjani" + r"\b")
PRIVATE_WORKSTATION_PATTERN = re.compile(r"\b" + "B-" + "Logy" + r"\b", re.IGNORECASE)


class ValidationError(RuntimeError):
    """A repository contract is absent, malformed, duplicated, or stale."""


def reject_duplicate_keys(pairs: list[tuple[str, Any]]) -> dict[str, Any]:
    result: dict[str, Any] = {}
    for key, value in pairs:
        if key in result:
            raise ValidationError(f"duplicate JSON key: {key!r}")
        result[key] = value
    return result


def load_json(path: Path) -> Any:
    try:
        with path.open("r", encoding="utf-8") as handle:
            return json.load(handle, object_pairs_hook=reject_duplicate_keys)
    except (OSError, UnicodeError, json.JSONDecodeError, ValidationError) as error:
        raise ValidationError(f"{path}: {error}") from error


def require(condition: bool, message: str) -> None:
    if not condition:
        raise ValidationError(message)


def validate_postgres_identifier_lengths(migrations: Path) -> tuple[int, int]:
    """Reject project-owned SQL identifiers PostgreSQL would silently truncate."""
    require(migrations.is_dir(), f"missing PostgreSQL migrations: {migrations}")
    identifiers: set[str] = set()
    for path in sorted(migrations.glob("*.sql")):
        source = path.read_text(encoding="utf-8")
        identifiers.update(POSTGRES_IDENTIFIER_PATTERN.findall(source))
    require(identifiers, "no AccordLock PostgreSQL identifiers found in migrations")
    encoded_lengths = {
        identifier: len(identifier.encode("utf-8")) for identifier in identifiers
    }
    overlong = sorted(
        (identifier, size)
        for identifier, size in encoded_lengths.items()
        if size > POSTGRES_IDENTIFIER_MAX_BYTES
    )
    require(
        not overlong,
        "PostgreSQL identifiers exceed the 63-byte limit: "
        + ", ".join(f"{identifier} ({size} bytes)" for identifier, size in overlong),
    )
    return len(identifiers), max(encoded_lengths.values())


def validate_broker_secret_name_contract(root: Path) -> tuple[str, int]:
    """Keep the deterministic broker Secret prefix and SQL length in sync."""
    migration = (
        root / "migrations" / "0009_broker_operation_journal.sql"
    ).read_text(encoding="utf-8")
    prefix_match = re.search(
        r"bound_secret_name\s*=\s*\n?\s*'(?P<prefix>[a-z0-9-]+)'\s*"
        r"\|\|\s*replace\(transaction_id::text,\s*'-',\s*''\)",
        migration,
    )
    length_match = re.search(
        r"octet_length\(bound_secret_name\)\s*=\s*(?P<length>\d+)",
        migration,
    )
    require(prefix_match is not None, "broker Secret prefix constraint is missing")
    require(length_match is not None, "broker Secret length constraint is missing")
    prefix = prefix_match.group("prefix")
    declared_length = int(length_match.group("length"))
    expected_length = len(prefix.encode("utf-8")) + 32
    require(
        declared_length == expected_length,
        "broker Secret SQL length differs from prefix plus compact UUID: "
        f"declared={declared_length} expected={expected_length}",
    )
    rust = (root / "crates" / "accordlock-state" / "src" / "broker.rs").read_text(
        encoding="utf-8"
    )
    require(
        f'format!("{prefix}{{}}", transaction_id.simple())' in rust,
        "Rust broker Secret derivation differs from the SQL prefix contract",
    )
    return prefix, declared_length


def _is_within(path: Path, root: Path) -> bool:
    try:
        path.relative_to(root)
    except ValueError:
        return False
    return True


def git_visible_files(root: Path) -> list[Path]:
    """Return tracked and unignored untracked files, or a source-archive fallback."""
    root = root.resolve()
    if (root / ".git").exists():
        try:
            result = subprocess.run(
                [
                    "git",
                    "-C",
                    str(root),
                    "ls-files",
                    "--cached",
                    "--others",
                    "--exclude-standard",
                    "-z",
                ],
                check=False,
                capture_output=True,
                timeout=15,
            )
        except (OSError, subprocess.SubprocessError) as error:
            raise ValidationError(f"cannot enumerate Git-visible files: {error}") from error
        require(
            result.returncode == 0,
            "cannot enumerate Git-visible files: git ls-files failed",
        )
        try:
            relatives = [
                item.decode("utf-8")
                for item in result.stdout.split(b"\0")
                if item
            ]
        except UnicodeError as error:
            raise ValidationError("Git-visible path is not valid UTF-8") from error
        paths = [root / relative for relative in relatives]
    else:
        excluded_roots = {
            ".git",
            ".lake",
            ".local",
            "__pycache__",
            "node_modules",
            "target",
        }
        paths = [
            path
            for path in root.rglob("*")
            if path.is_file()
            and not any(
                part in excluded_roots or part.startswith(".tmp")
                for part in path.relative_to(root).parts
            )
            and path.relative_to(root).parts[:2] != ("models", "states")
        ]

    visible: list[Path] = []
    for path in paths:
        resolved = path.resolve()
        require(
            _is_within(resolved, root),
            f"Git-visible path escapes the repository: {path}",
        )
        require(path.is_file(), f"Git-visible path is not a regular file: {path}")
        visible.append(path)
    return sorted(
        set(visible),
        key=lambda path: path.relative_to(root).as_posix().casefold(),
    )


def validate_no_legacy_brand(root: Path, visible_paths: list[Path]) -> None:
    root = root.resolve()
    legacy_text = LEGACY_BRAND_BYTES.decode("ascii")
    for path in visible_paths:
        relative = path.relative_to(root).as_posix()
        require(
            legacy_text not in relative.casefold(),
            f"legacy brand remains in Git-visible path: {relative}",
        )
        try:
            content = path.read_bytes()
        except OSError as error:
            raise ValidationError(f"cannot read Git-visible file {relative}: {error}") from error
        require(
            LEGACY_BRAND_BYTES not in content.lower(),
            f"legacy brand remains in Git-visible content: {relative}",
        )


def _normalized_search_text(source: str) -> str:
    """Return accent-insensitive text without changing the published source."""
    return "".join(
        character
        for character in unicodedata.normalize("NFKD", source)
        if not unicodedata.combining(character)
    )


def _is_safe_credential_vector(relative: str, line: str, value: str) -> bool:
    """Allow only explicit, obviously synthetic credentials in fixture trees."""
    if not relative.startswith(SAFE_CREDENTIAL_VECTOR_PREFIXES):
        return False
    if SAFE_CREDENTIAL_VECTOR_MARKER not in line.casefold():
        return False
    normalized = re.sub(r"[^A-Za-z0-9]", "", value)
    return bool(normalized) and len(set(normalized)) <= 4


def validate_runtime_artifact_paths(root: Path, visible_paths: list[Path]) -> None:
    """Reject credentials, local databases, logs, caches, and process artifacts."""
    root = root.resolve()
    for path in visible_paths:
        relative = path.resolve().relative_to(root).as_posix()
        parts = tuple(part.casefold() for part in Path(relative).parts)
        name = parts[-1]
        require(
            not any(part in RUNTIME_ARTIFACT_DIRECTORIES for part in parts[:-1]),
            f"runtime cache directory is Git-visible: {relative}",
        )
        env_artifact = name == ".env" or (
            name.startswith(".env.") and name not in SAFE_ENV_TEMPLATE_NAMES
        )
        require(not env_artifact, f"runtime environment file is Git-visible: {relative}")
        require(
            name not in RUNTIME_ARTIFACT_NAMES
            and Path(name).suffix.casefold() not in RUNTIME_ARTIFACT_SUFFIXES,
            f"runtime or credential artifact is Git-visible: {relative}",
        )


def validate_publication_content(root: Path, visible_paths: list[Path]) -> None:
    """Reject internal terminology, private paths, non-English copy, and credentials."""
    root = root.resolve()
    for path in visible_paths:
        relative = path.resolve().relative_to(root).as_posix()
        try:
            raw = path.read_bytes()
        except OSError as error:
            raise ValidationError(f"cannot read Git-visible file {relative}: {error}") from error
        if b"\0" in raw:
            continue
        try:
            source = raw.decode("utf-8")
        except UnicodeError as error:
            raise ValidationError(
                f"Git-visible text is not valid UTF-8: {relative}"
            ) from error

        path_and_source = relative + "\n" + source
        for label, pattern in OBSOLETE_TERMINOLOGY_PATTERNS:
            match = pattern.search(path_and_source)
            require(match is None, f"{label} remains in Git-visible file: {relative}")

        normalized = _normalized_search_text(source)
        require(
            NON_ENGLISH_PRODUCT_COPY_PATTERN.search(normalized) is None,
            f"non-English product copy remains in Git-visible file: {relative}",
        )
        for pattern in PRIVATE_PATH_PATTERNS:
            require(
                pattern.search(source) is None,
                f"personal absolute path remains in Git-visible file: {relative}",
            )
        require(
            PRIVATE_WORKSTATION_PATTERN.search(source) is None,
            f"private workstation identifier remains in Git-visible file: {relative}",
        )
        if relative not in LEGAL_ATTRIBUTION_FILES:
            require(
                LEGAL_AUTHOR_PATTERN.search(source) is None,
                f"personal name appears outside legal attribution metadata: {relative}",
            )

        for line_number, line in enumerate(source.splitlines(), start=1):
            for label, pattern in CREDENTIAL_PATTERNS:
                for match in pattern.finditer(line):
                    require(
                        _is_safe_credential_vector(relative, line, match.group(0)),
                        f"possible {label} in {relative}:{line_number}",
                    )


def _markdown_targets(source: str) -> list[str]:
    without_fences = re.sub(
        r"(?ms)^(?P<fence>`{3,}|~{3,})[^\r\n]*\r?\n.*?^(?P=fence)\s*$",
        "",
        source,
    )
    without_inline_code = re.sub(r"`[^`\r\n]*`", "", without_fences)
    return [
        match.group("target")
        for pattern in (MARKDOWN_LINK_PATTERN, MARKDOWN_REFERENCE_PATTERN)
        for match in pattern.finditer(without_inline_code)
    ]


def _local_markdown_target(raw_target: str, markdown_path: Path, root: Path) -> Path | None:
    target = raw_target.strip()
    if target.startswith("<") and target.endswith(">"):
        target = target[1:-1].strip()
    else:
        target = target.split(maxsplit=1)[0]
    target = unquote(target.replace(r"\(", "(").replace(r"\)", ")"))
    if not target or target.startswith("#"):
        return None

    lowered = target.casefold()
    require(not lowered.startswith("file:"), f"file URI in {markdown_path}: {target}")
    require(
        not re.match(r"^[a-zA-Z]:[\\/]", target)
        and not target.startswith(("/", "\\")),
        f"absolute local path in {markdown_path}: {target}",
    )
    if re.match(r"^[a-zA-Z][a-zA-Z0-9+.-]*:", target):
        return None

    path_text = target.split("#", 1)[0].split("?", 1)[0]
    if not path_text:
        return None
    resolved = (markdown_path.parent / path_text).resolve()
    require(
        _is_within(resolved, root),
        f"relative Markdown link escapes repository in {markdown_path}: {target}",
    )
    return resolved


def validate_markdown_links(root: Path, visible_paths: list[Path]) -> int:
    root = root.resolve()
    checked = 0
    for path in visible_paths:
        if path.suffix.casefold() not in {".md", ".markdown"}:
            continue
        try:
            source = path.read_text(encoding="utf-8")
        except (OSError, UnicodeError) as error:
            raise ValidationError(f"cannot read Markdown file {path}: {error}") from error
        for raw_target in _markdown_targets(source):
            target = _local_markdown_target(raw_target, path, root)
            if target is None:
                continue
            checked += 1
            require(
                target.exists(),
                f"broken relative Markdown link in {path.relative_to(root)}: {raw_target}",
            )
    return checked


def validate_publication_hygiene(
    root: Path, visible_paths: list[Path] | None = None
) -> tuple[int, int]:
    root = root.resolve()
    paths = git_visible_files(root) if visible_paths is None else visible_paths
    relative_files = {path.resolve().relative_to(root).as_posix() for path in paths}
    missing = sorted(set(PUBLICATION_REQUIRED_FILES) - relative_files)
    require(not missing, f"required public repository files are absent: {missing}")
    validate_no_legacy_brand(root, paths)
    validate_runtime_artifact_paths(root, paths)
    validate_publication_content(root, paths)
    checked_links = validate_markdown_links(root, paths)
    return len(paths), checked_links


def validate_third_party_attribution(root: Path) -> None:
    """Keep the Contributor Covenant source, license, and changes explicit."""
    code_of_conduct = (root / "CODE_OF_CONDUCT.md").read_text(encoding="utf-8")
    notice = (root / "NOTICE").read_text(encoding="utf-8")
    required_code_of_conduct_markers = (
        "Contributor Covenant, version",
        "https://www.contributor-covenant.org/version/2/1/code_of_conduct/",
        "Creative Commons Attribution 4.0 International",
        "https://creativecommons.org/licenses/by/4.0/",
        "AccordLock changed",
    )
    for marker in required_code_of_conduct_markers:
        require(
            marker in code_of_conduct,
            f"CODE_OF_CONDUCT.md is missing attribution marker: {marker}",
        )
    for marker in (
        "CODE_OF_CONDUCT.md",
        "Contributor Covenant version",
        "Creative Commons Attribution",
    ):
        require(marker in notice, f"NOTICE is missing third-party marker: {marker}")


def validate_json_documents(root: Path) -> int:
    paths = sorted((root / "conformance").rglob("*.json"))
    paths += sorted((root / "schemas").rglob("*.json"))
    require(paths, "no JSON contracts found")
    for path in paths:
        load_json(path)
    return len(paths)


def validate_corpus(root: Path) -> int:
    corpus_path = root / "conformance" / "corpus.json"
    corpus = load_json(corpus_path)
    require(isinstance(corpus, dict), f"{corpus_path}: root must be an object")
    require(corpus.get("strict_json") is True, "corpus must declare strict_json=true")
    require(
        corpus.get("scenario_manifest_schema") == "accordlock.conformance.scenario.v0.1",
        "unexpected scenario manifest schema",
    )

    groups = (
        "positive_controls",
        "primary_differential_scenarios",
        "repaired_twins",
    )
    references: list[str] = []
    declared_counts = corpus.get("declared_counts")
    require(isinstance(declared_counts, dict), "declared_counts must be an object")
    for group in groups:
        entries = corpus.get(group)
        require(isinstance(entries, list), f"{group} must be an array")
        require(all(isinstance(item, str) for item in entries), f"{group} must contain paths")
        require(
            declared_counts.get(group) == len(entries),
            f"declared count for {group} does not match the index",
        )
        references.extend(entries)

    require(len(references) == len(set(references)), "scenario index contains duplicate paths")
    require(
        declared_counts.get("scenario_manifests_total") == len(references),
        "scenario_manifests_total is stale",
    )

    indexed_paths = {(root / "conformance" / item).resolve() for item in references}
    actual_paths = {path.resolve() for path in (root / "conformance" / "scenarios").glob("*.json")}
    require(indexed_paths == actual_paths, "scenario index and scenario directory differ")

    scenario_ids: set[str] = set()
    for path in sorted(indexed_paths):
        scenario = load_json(path)
        require(isinstance(scenario, dict), f"{path}: root must be an object")
        require(
            scenario.get("schema_version") == corpus["scenario_manifest_schema"],
            f"{path}: schema_version does not match corpus index",
        )
        identifier = scenario.get("id")
        require(identifier == path.stem, f"{path}: id must equal file stem")
        require(identifier not in scenario_ids, f"duplicate scenario id: {identifier}")
        scenario_ids.add(identifier)
        fixture_ref = scenario.get("fixture_ref")
        require(isinstance(fixture_ref, str) and "#" in fixture_ref, f"{path}: invalid fixture_ref")
        relative, fragment = fixture_ref.split("#", 1)
        fixture_path = (path.parent / relative).resolve()
        fixture = load_json(fixture_path)
        require(
            isinstance(fixture, dict) and fixture.get("fixture_id") == fragment,
            f"{path}: fixture fragment does not identify fixture_id",
        )

    return len(references)


def enum_block(source: str, enum_name: str) -> str:
    match = re.search(rf"pub enum {re.escape(enum_name)}\s*\{{(?P<body>.*?)\n\}}", source, re.S)
    if not match:
        raise ValidationError(f"could not find Rust enum {enum_name}")
    return match.group("body")


def validate_reason_codes(root: Path) -> int:
    registry_path = root / "schemas" / "reason-codes.json"
    registry = load_json(registry_path)
    require(isinstance(registry, dict), "reason registry root must be an object")
    entries = registry.get("codes")
    require(isinstance(entries, list) and entries, "reason registry codes must be non-empty")

    numeric = [entry.get("code") for entry in entries if isinstance(entry, dict)]
    names = [entry.get("name") for entry in entries if isinstance(entry, dict)]
    variants = [entry.get("rust_variant") for entry in entries if isinstance(entry, dict)]
    require(len(numeric) == len(entries), "reason entries must be objects")
    require(numeric == list(range(len(entries))), "reason numeric codes must be contiguous from zero")
    require(len(names) == len(set(names)), "reason names are not unique")
    require(len(variants) == len(set(variants)), "reason Rust variants are not unique")
    require(registry.get("invariants", {}).get("allowed_code") == 0, "allowed_code must be zero")

    rust_path = root / "crates" / "accordlock-protocol" / "src" / "types.rs"
    rust = rust_path.read_text(encoding="utf-8")
    variants_in_enum = re.findall(r"^\s*([A-Z][A-Za-z0-9_]*)\s*,\s*$", enum_block(rust, "ReasonCode"), re.M)
    mapping_match = re.search(
        r"impl ReasonCode\s*\{.*?pub const fn code\(self\) -> u16\s*\{\s*match self\s*\{(?P<body>.*?)\n\s*\}\s*\n\s*\}",
        rust,
        re.S,
    )
    require(mapping_match is not None, "could not find ReasonCode::code mapping")
    mapping_pairs = re.findall(r"Self::([A-Z][A-Za-z0-9_]*)\s*=>\s*(\d+)", mapping_match.group("body"))
    rust_mapping = [(variant, int(code)) for variant, code in mapping_pairs]
    registry_mapping = list(zip(variants, numeric, strict=True))
    require(variants_in_enum == variants, "reason registry variants differ from Rust enum order")
    require(rust_mapping == registry_mapping, "reason registry differs from ReasonCode::code")

    cddl = (root / "schemas" / "accordlock-local-candidate.cddl").read_text(encoding="utf-8")
    range_match = re.search(r"^reason-code\s*=\s*(\d+)\.\.(\d+)\s*$", cddl, re.M)
    require(range_match is not None, "CDDL reason-code range is absent")
    require(
        (int(range_match.group(1)), int(range_match.group(2))) == (0, len(entries) - 1),
        "CDDL reason-code range is stale",
    )
    return len(entries)


def cddl_array_field_count(cddl: str, name: str) -> int:
    match = re.search(rf"^{re.escape(name)}\s*=\s*\[(?P<body>.*?)^\]", cddl, re.M | re.S)
    if not match:
        raise ValidationError(f"CDDL array definition absent: {name}")
    return len(re.findall(r"^\s*[a-z][a-z0-9-]*\s*:", match.group("body"), re.M))


def validate_cddl_rust_array_contract(root: Path) -> int:
    cddl = (root / "schemas" / "accordlock-local-candidate.cddl").read_text(encoding="utf-8")
    rust = (root / "crates" / "accordlock-protocol" / "src" / "canonical.rs").read_text(encoding="utf-8")
    expected = {
        "authority-domain-state-cbor": 3,
        "authority-vector-cbor": 12,
        "review-evidence-payload-cbor": 5,
        "build-evidence-payload-cbor": 9,
        "artifact-evidence-payload-cbor": 6,
        "target-evidence-payload-cbor": 8,
        "evidence-assertion-cbor": 10,
        "deployment-template-cbor": 19,
        "policy-config-cbor": 10,
        "evaluation-attestation-cbor": 15,
        "capability-grant-cbor": 15,
        "dispatch-deadline-policy-cbor": 3,
        "execution-authorization-cbor": 20,
        "consumption-receipt-cbor": 8,
    }
    for name, count in expected.items():
        require(cddl_array_field_count(cddl, name) == count, f"CDDL array arity stale: {name}")

    required_rust_patterns = (
        r"fn encode_domain\(.*?encoder\.array\(3\)\?",
        r"fn encode_authority\(.*?encoder\.array\(12\)\?",
        r"fn encode_template\(.*?encoder\.array\(19\)\?",
        r"fn encode_assertion\(.*?encoder\.array\(10\)\?",
        r"impl CanonicalEncode for PolicyConfig.*?encoder\.array\(10\)\?",
        r"impl CanonicalEncode for EvaluationAttestation.*?encoder\.array\(15\)\?",
        r"impl CanonicalEncode for CapabilityGrant.*?encoder\.array\(15\)\?",
        r"fn encode_dispatch_deadline_policy\(.*?encoder\.array\(3\)\?",
        r"impl CanonicalEncode for ExecutionAuthorization.*?encoder\.array\(20\)\?",
        r"impl CanonicalEncode for ConsumptionReceipt.*?encoder\.array\(8\)\?",
    )
    for pattern in required_rust_patterns:
        require(re.search(pattern, rust, re.S) is not None, f"canonical Rust contract changed: {pattern}")
    payload_match = re.search(r"fn encode_payload\(.*?\n\}", rust, re.S)
    require(payload_match is not None, "encode_payload is absent")
    payload_arities = [int(item) for item in re.findall(r"encoder\.array\((\d+)\)\?", payload_match.group(0))]
    require(payload_arities == [5, 9, 6, 8], "evidence payload Rust array arities changed")
    return len(expected)


def validate_k8s_runner_patch_handoff(root: Path) -> None:
    runner = (root / "infra" / "local" / "k8s" / "run-live.ps1").read_text(
        encoding="utf-8"
    )
    require("--patch-file" not in runner, "live runner reopens a mutable patch path")
    require(
        runner.count("'--patch', $PatchJson") == 2,
        "dry-run and real Kubernetes calls must share one in-memory patch value",
    )
    read_once = runner.count(
        "$PatchJson = [System.IO.File]::ReadAllText((Resolve-Path -LiteralPath $PatchPath))"
    )
    require(read_once == 1, "live runner must read the generated patch exactly once")
    cgroup_query = "'info', '--format', '{{.CgroupVersion}}'"
    cgroup_refusal = "requires Docker cgroup v2"
    inventory_stage = "Start-RunnerStage -Name 'Inspect kind cluster and kubeconfig state'"
    require(cgroup_query in runner, "live runner does not inspect Docker cgroup version")
    require(cgroup_refusal in runner, "live runner does not refuse incompatible cgroup v1")
    require(
        runner.index(cgroup_query) < runner.index(inventory_stage),
        "Docker cgroup compatibility must be checked before cluster inspection or mutation",
    )


def validate_docker_secret_exclusions(root: Path) -> int:
    dockerignore = (root / ".dockerignore").read_text(encoding="utf-8")
    patterns = {
        line.strip()
        for line in dockerignore.splitlines()
        if line.strip() and not line.lstrip().startswith("#")
    }
    required = {
        ".env*",
        "**/.env*",
        "*.key",
        "**/*.key",
        "*.pem",
        "**/*.pem",
        "*.p12",
        "**/*.p12",
        "*.pfx",
        "**/*.pfx",
        "**/secrets/**",
        "**/secret/**",
        "**/password",
        "**/password.*",
    }
    missing = sorted(required - patterns)
    require(not missing, f"Docker context can include ignored secrets: {missing}")
    return len(required)


def validate_postgres_upgrade_reset_guard(root: Path) -> None:
    confirmation = "DROP_PUBLIC_SCHEMA_OF_ACCORDLOCK_TEST_V2"
    state_suite = (
        root / "crates" / "accordlock-state" / "tests" / "postgres.rs"
    ).read_text(encoding="utf-8")
    upgrade = (
        root / "crates" / "accordlock-state" / "tests" / "postgres_v14_upgrade.rs"
    ).read_text(encoding="utf-8")
    require(
        "ACCORDLOCK_TEST_DATABASE_URL" not in state_suite,
        "historical rebuild test can be redirected by an ambient database URL",
    )
    for marker in (
        "ACCORDLOCK_TEST_POSTGRES_URL",
        "ACCORDLOCK_TEST_POSTGRES_V14_RESET",
        confirmation,
        'const DISPOSABLE_DATABASE_NAME: &str = "accordlock_test_v2"',
        "validate_historical_rebuild_target(url, confirmation.as_deref())",
        "postgres_historical_rebuild_target_guard_is_fail_closed",
    ):
        require(
            marker in state_suite,
            f"historical rebuild destructive guard is absent: {marker}",
        )
    require(
        state_suite.count("configured_historical_rebuild_store()") == 4,
        "all three historical rebuild tests must validate the target before connecting",
    )
    require(
        "ACCORDLOCK_TEST_DATABASE_URL" not in upgrade,
        "v14 upgrade test can be redirected by an ambient database URL",
    )
    for marker in (
        "ACCORDLOCK_TEST_POSTGRES_URL",
        "ACCORDLOCK_TEST_POSTGRES_V14_RESET",
        confirmation,
        'const DISPOSABLE_DATABASE_NAME: &str = "accordlock_test_v2"',
        "validate_destructive_test_target(&url, confirmation.as_deref())",
    ):
        require(marker in upgrade, f"v14 upgrade destructive guard is absent: {marker}")
    for runner in (root / "scripts" / "run-all.ps1", root / "scripts" / "run-all.sh"):
        source = runner.read_text(encoding="utf-8")
        require(
            f"ACCORDLOCK_TEST_POSTGRES_V14_RESET={confirmation}" in source
            or f"ACCORDLOCK_TEST_POSTGRES_V14_RESET = '{confirmation}'" in source,
            f"{runner}: upgrade reset confirmation is not command-scoped",
        )
    shell_runner = (root / "scripts" / "run-all.sh").read_text(encoding="utf-8")
    require(
        "export ACCORDLOCK_TEST_POSTGRES_V14_RESET" not in shell_runner,
        "run-all.sh exports the destructive reset confirmation beyond the upgrade process",
    )
    required_shell_fragment = (
        "run_stage postgres_v14_upgrade_invariants env \\\n"
        f"            ACCORDLOCK_TEST_POSTGRES_V14_RESET={confirmation}"
    )
    require(
        required_shell_fragment in shell_runner,
        "run-all.sh does not scope the local reset confirmation to the upgrade command",
    )
    required_state_shell_fragment = (
        "run_stage postgres_state_adversarial_invariants env \\\n"
        f"            ACCORDLOCK_TEST_POSTGRES_V14_RESET={confirmation}"
    )
    require(
        required_state_shell_fragment in shell_runner,
        "run-all.sh does not scope the local reset confirmation to the state command",
    )
    powershell_runner = (root / "scripts" / "run-all.ps1").read_text(encoding="utf-8")
    for marker in (
        "$previousStateResetConfirmation = $env:ACCORDLOCK_TEST_POSTGRES_V14_RESET",
        "Invoke-AccordLockStage -Name 'postgres_state_adversarial_invariants'",
        "$previousResetConfirmation = $env:ACCORDLOCK_TEST_POSTGRES_V14_RESET",
        "Invoke-AccordLockStage -Name 'postgres_v14_upgrade_invariants'",
    ):
        require(marker in powershell_runner, f"run-all.ps1 reset scope is absent: {marker}")
    for workflow_name in (
        "reproducibility.yml",
        "reproducibility-exhaustive.yml",
    ):
        workflow = (
            root / ".github" / "workflows" / workflow_name
        ).read_text(encoding="utf-8")
        for marker in (
            "POSTGRES_DB: accordlock_test_v2",
            'pg_isready -U postgres -d accordlock_test_v2',
            "ACCORDLOCK_TEST_POSTGRES_URL: postgresql://postgres@127.0.0.1:5432/accordlock_test_v2",
            f"ACCORDLOCK_TEST_POSTGRES_V14_RESET: {confirmation}",
        ):
            require(
                marker in workflow,
                f"{workflow_name}: reproducibility reset guard is absent: {marker}",
            )
        require(
            workflow.count("ACCORDLOCK_TEST_POSTGRES_V14_RESET:") == 1,
            f"{workflow_name}: reset confirmation must be scoped to one step",
        )


def tla_config_constants(source: str, label: str) -> dict[str, str]:
    match = re.search(
        r"^CONSTANTS\s*$\n(?P<body>.*?)(?=^(?:VIEW|INVARIANTS)\b)",
        source,
        re.M | re.S,
    )
    require(match is not None, f"{label}: CONSTANTS block is absent")
    constants: dict[str, str] = {}
    for name, value in re.findall(
        r"^\s+([A-Za-z][A-Za-z0-9_]*)\s*=\s*(\S(?:.*\S)?)\s*$",
        match.group("body"),
        re.M,
    ):
        require(name not in constants, f"{label}: duplicate constant {name}")
        constants[name] = re.sub(r"\s+", "", value)
    require(constants, f"{label}: no constants parsed")
    return constants


def tla_config_invariants(source: str, label: str) -> list[str]:
    match = re.search(r"^INVARIANTS\s*$\n(?P<body>.*)\Z", source, re.M | re.S)
    require(match is not None, f"{label}: INVARIANTS block is absent")
    invariants = [
        line.strip()
        for line in match.group("body").splitlines()
        if line.strip()
    ]
    require(
        invariants and all(re.fullmatch(r"[A-Za-z][A-Za-z0-9_]*", item) for item in invariants),
        f"{label}: malformed invariant list",
    )
    require(len(invariants) == len(set(invariants)), f"{label}: duplicate invariant")
    return invariants


def validate_dda_config_directives(source: str, label: str) -> None:
    view_directives = re.findall(r"^[ \t]*VIEW\b[^\r\n]*$", source, re.M)
    require(
        len(view_directives) == 1
        and re.fullmatch(r"[ \t]*VIEW[ \t]+SafetyView[ \t]*", view_directives[0])
        is not None,
        f"{label}: must contain exactly VIEW SafetyView",
    )
    require(
        re.search(r"^[ \t]*SYMMETRY\b", source, re.M) is None,
        f"{label}: SYMMETRY directives are forbidden",
    )


def validate_dda_model_contract(source: str) -> None:
    required_operators = (
        r"^PersistedWorkers[ \t]*==",
        r"^CanonicalFreshRequestId\(requestId\)[ \t]*==",
        r"^CanonicalPersistentWorker\(worker\)[ \t]*==",
        r"^UnusedRequestIds[ \t]*==",
        r"^CanonicalObservationRequestId[ \t]*==",
        r"^CanonicalObservationWorker[ \t]*==",
        r"^SafetyProofVector[ \t]*==",
    )
    for pattern in required_operators:
        require(
            len(re.findall(pattern, source, re.M)) == 1,
            "DurableDispatchAcquisition.tla: required operator is absent or "
            f"duplicated: {pattern}",
        )
    require(
        len(
            re.findall(
                r"^SafetyView[ \t]*==[ \t]*\r?\n[ \t]+IF[ \t]+TypeOK\b",
                source,
                re.M,
            )
        )
        == 1,
        "DurableDispatchAcquisition.tla: SafetyView must fail closed through IF TypeOK",
    )


def validate_tla_ci_separation(root: Path) -> None:
    scripts = root / "scripts"
    models = root / "models"
    workflows = root / ".github" / "workflows"
    canonical_model_names = [
        "AuthorizationLifecycle",
        "DispatchClaim",
        "PhysicalReservation",
        "AdmissionAuthorization",
        "BrokerJournal",
        "TerminalRetirement",
        "DurableControlQueue",
        "DurableDispatchAcquisition",
    ]
    first_seven = canonical_model_names[:-1]

    canonical_cfg = (models / "DurableDispatchAcquisition.cfg").read_text(
        encoding="utf-8"
    )
    bounded_max2_cfg = (
        models / "DurableDispatchAcquisitionBoundedMax2.cfg"
    ).read_text(encoding="utf-8")
    smoke_cfg = (models / "DurableDispatchAcquisitionSmoke.cfg").read_text(
        encoding="utf-8"
    )
    dda_model = (models / "DurableDispatchAcquisition.tla").read_text(
        encoding="utf-8"
    )
    validate_dda_model_contract(dda_model)
    canonical_constants = tla_config_constants(canonical_cfg, "canonical DDA config")
    bounded_max2_constants = tla_config_constants(
        bounded_max2_cfg, "bounded Max2 DDA config"
    )
    smoke_constants = tla_config_constants(smoke_cfg, "smoke DDA config")
    for label, constants in (
        ("bounded Max2 DDA", bounded_max2_constants),
        ("smoke DDA", smoke_constants),
    ):
        require(
            set(constants) == set(canonical_constants),
            f"{label} constants differ from the canonical constant set",
        )
    require(
        canonical_constants.get("MaxAcquisitions") == "3"
        and bounded_max2_constants.get("MaxAcquisitions") == "2"
        and smoke_constants.get("MaxAcquisitions") == "1",
        "DDA configurations must preserve the canonical Max3, bounded Max2, and smoke Max1 tiers",
    )
    require(
        canonical_constants.get("AcquisitionIds")
        == "{acquisition_a,acquisition_b,acquisition_c}"
        and bounded_max2_constants.get("AcquisitionIds")
        == "{acquisition_a,acquisition_b}"
        and smoke_constants.get("AcquisitionIds") == "{acquisition_a}",
        "DDA acquisition identifiers do not match the Max3, Max2, and Max1 bounds",
    )
    for label, constants in (
        ("bounded Max2 DDA", bounded_max2_constants),
        ("smoke DDA", smoke_constants),
    ):
        for name in set(canonical_constants) - {"MaxAcquisitions", "AcquisitionIds"}:
            require(
                constants[name] == canonical_constants[name],
                f"{label} changes canonical constant {name}",
            )
    canonical_invariants = tla_config_invariants(
        canonical_cfg, "canonical DDA config"
    )
    for label, source in (
        ("bounded Max2 DDA config", bounded_max2_cfg),
        ("smoke DDA config", smoke_cfg),
    ):
        require(
            tla_config_invariants(source, label) == canonical_invariants,
            f"{label} and canonical invariant lists differ",
        )
    for label, source in (
        ("canonical DDA config", canonical_cfg),
        ("bounded Max2 DDA config", bounded_max2_cfg),
        ("smoke DDA config", smoke_cfg),
    ):
        validate_dda_config_directives(source, label)

    exhaustive_sh = (scripts / "run-tla.sh").read_text(encoding="utf-8")
    exhaustive_ps = (scripts / "run-tla.ps1").read_text(encoding="utf-8")
    smoke_sh = (scripts / "run-tla-smoke.sh").read_text(encoding="utf-8")
    smoke_ps = (scripts / "run-tla-smoke.ps1").read_text(encoding="utf-8")
    expected_shell_models = "models='" + " ".join(canonical_model_names) + "'"
    require(
        expected_shell_models in exhaustive_sh and "Smoke.cfg" not in exhaustive_sh,
        "default shell TLA runner must execute exactly eight canonical configs",
    )
    exhaustive_ps_models = re.search(
        r"\$models\s*=\s*@\((?P<body>.*?)\n\)", exhaustive_ps, re.S
    )
    require(exhaustive_ps_models is not None, "default PowerShell TLA model list absent")
    require(
        re.findall(r"'([^']+)'", exhaustive_ps_models.group("body"))
        == canonical_model_names
        and "Smoke.cfg" not in exhaustive_ps,
        "default PowerShell TLA runner must execute exactly eight canonical configs",
    )
    require(
        exhaustive_sh.count("-workers 1") == 1
        and exhaustive_ps.count("-workers 1") == 1,
        "default TLA runners must force one worker",
    )

    expected_smoke_shell_models = "canonical_models='" + " ".join(first_seven) + "'"
    require(
        expected_smoke_shell_models in smoke_sh,
        "shell smoke runner must retain the first seven canonical configs",
    )
    smoke_ps_models = re.search(
        r"\$canonicalModels\s*=\s*@\((?P<body>.*?)\n\)", smoke_ps, re.S
    )
    require(smoke_ps_models is not None, "PowerShell smoke model list absent")
    require(
        re.findall(r"'([^']+)'", smoke_ps_models.group("body")) == first_seven,
        "PowerShell smoke runner must retain the first seven canonical configs",
    )
    for label, source, smoke_path, canonical_path in (
        (
            "shell",
            smoke_sh,
            "models/DurableDispatchAcquisitionSmoke.cfg",
            "models/DurableDispatchAcquisition.cfg",
        ),
        (
            "PowerShell",
            smoke_ps,
            "models\\DurableDispatchAcquisitionSmoke.cfg",
            "models\\DurableDispatchAcquisition.cfg",
        ),
    ):
        require(
            smoke_path in source and canonical_path not in source,
            f"{label} smoke runner must use only the DDA smoke config for DDA",
        )
        require(
            "DurableDispatchAcquisitionBoundedMax2.cfg" not in source
            and "smoke_max_acquisitions_1_full_search" in source,
            f"{label} smoke runner must identify Max1 full-search coverage and exclude Max2",
        )
        require(
            source.count("-workers auto") == 2 and "-workers 1" not in source,
            f"{label} smoke runner must use TLC automatic worker selection for all invocations",
        )
        require(
            "PASS tla_model_check_smoke" in source
            and "not the canonical exhaustive" in source,
            f"{label} smoke result is not explicitly bounded",
        )

    run_all_sh = (scripts / "run-all.sh").read_text(encoding="utf-8")
    run_all_ps = (scripts / "run-all.ps1").read_text(encoding="utf-8")
    for marker in (
        "tla_mode=${ACCORDLOCK_TLA_MODE:-exhaustive}",
        'exhaustive|smoke) ;;',
        'run_stage tla_model_check_smoke sh "$repository_root/scripts/run-tla-smoke.sh"',
        'run_stage tla_model_check "$repository_root/scripts/run-tla.sh"',
        "PASS run_all_smoke",
        "BOUNDARY run_all_smoke is not a full or exhaustive reproducibility result",
        "tla_mode=exhaustive",
        "postgres_v14_scan_skips_more_than_transient_retry_cap_and_reaches_valid_tail",
        "run_all_smoke excludes the 257-head PostgreSQL scan retained by exhaustive mode",
    ):
        require(marker in run_all_sh, f"run-all.sh TLA mode separation absent: {marker}")
    for marker in (
        "[ValidateSet('exhaustive', 'smoke')]",
        "$env:ACCORDLOCK_TLA_MODE",
        "run-tla-smoke.ps1",
        "run-tla.ps1",
        "PASS run_all_smoke",
        "BOUNDARY run_all_smoke is not a full or exhaustive reproducibility result",
        "tla_mode=exhaustive",
        "postgres_v14_scan_skips_more_than_transient_retry_cap_and_reaches_valid_tail",
        "run_all_smoke excludes the 257-head PostgreSQL scan retained by exhaustive mode",
    ):
        require(marker in run_all_ps, f"run-all.ps1 TLA mode separation absent: {marker}")

    heavy_postgres_test = (
        "postgres_v14_scan_skips_more_than_transient_retry_cap_and_reaches_valid_tail"
    )
    control_test_source = (
        root / "crates" / "accordlock-state" / "tests" / "postgres_control_v13.rs"
    ).read_text(encoding="utf-8")
    require(
        control_test_source.count(f"fn {heavy_postgres_test}()") == 1
        and "intentionally builds 257 durable recovery heads" in control_test_source,
        "the exhaustive 257-head PostgreSQL test is absent or no longer explicit",
    )
    require(
        run_all_sh.count(heavy_postgres_test) == 1
        and run_all_ps.count(heavy_postgres_test) == 1,
        "smoke runners must skip exactly the named 257-head PostgreSQL test",
    )
    require(
        "if [ \"$tla_mode\" = smoke ]; then" in run_all_sh
        and "if ($TlaMode -eq 'smoke')" in run_all_ps,
        "the 257-head PostgreSQL exclusion must remain smoke-only",
    )

    smoke_workflow = (workflows / "reproducibility.yml").read_text(encoding="utf-8")
    exhaustive_workflow = (
        workflows / "reproducibility-exhaustive.yml"
    ).read_text(encoding="utf-8")
    smoke_triggers = smoke_workflow.split("permissions:", 1)[0]
    exhaustive_triggers = exhaustive_workflow.split("permissions:", 1)[0]
    require(
        smoke_workflow.count("name: reproducibility-smoke") == 2
        and "full-local-candidate" not in smoke_workflow,
        "hosted workflow name and status must both identify smoke coverage",
    )
    require(
        "\n  push:\n" in smoke_triggers and "\n  pull_request:\n" in smoke_triggers,
        "hosted smoke workflow must run for pushes and pull requests",
    )
    require(
        "runs-on: ubuntu-24.04" in smoke_workflow
        and "timeout-minutes: 120" in smoke_workflow,
        "hosted smoke workflow runner or timeout changed",
    )
    require(
        smoke_workflow.count("ACCORDLOCK_TLA_MODE: smoke") == 1
        and smoke_workflow.count("run: sh scripts/run-all.sh") == 1,
        "hosted workflow must explicitly call run-all in smoke mode once",
    )
    require(
        "      - name: Run fail-closed reproducibility smoke suite\n"
        "        env:\n"
        "          ACCORDLOCK_TLA_MODE: smoke\n"
        "          ACCORDLOCK_TEST_POSTGRES_V14_RESET: DROP_PUBLIC_SCHEMA_OF_ACCORDLOCK_TEST_V2\n"
        "        run: sh scripts/run-all.sh"
        in smoke_workflow,
        "hosted smoke mode and reset confirmation must be scoped to the run-all step",
    )
    require(
        exhaustive_workflow.count("name: reproducibility-exhaustive") == 2,
        "exhaustive workflow name and status are not explicit",
    )
    require(
        "\n  workflow_dispatch:\n" in exhaustive_triggers
        and "\n  push:\n" not in exhaustive_triggers
        and "\n  schedule:\n" not in exhaustive_triggers
        and "pull_request:" not in exhaustive_triggers,
        "technical-preview exhaustive workflow must remain manual-only until its self-hosted runner is provisioned",
    )
    require(
        "runs-on: [self-hosted, linux, x64, accordlock-tlc]" in exhaustive_workflow,
        "exhaustive workflow must use the labelled self-hosted TLC runner",
    )
    timeout = re.search(r"timeout-minutes:\s*(\d+)", exhaustive_workflow)
    require(
        timeout is not None and 7000 <= int(timeout.group(1)) < 7200,
        "exhaustive timeout must be close to, but below, five days",
    )
    require(
        "ACCORDLOCK_TLA_MODE" not in exhaustive_workflow
        and exhaustive_workflow.count("run: sh scripts/run-all.sh") == 1,
        "exhaustive workflow must call the exact default run-all command once",
    )
    require(
        "      - name: Run fail-closed exhaustive reproducibility suite\n"
        "        env:\n"
        "          ACCORDLOCK_TEST_POSTGRES_V14_RESET: DROP_PUBLIC_SCHEMA_OF_ACCORDLOCK_TEST_V2\n"
        "        run: sh scripts/run-all.sh"
        in exhaustive_workflow,
        "exhaustive reset confirmation must be scoped to the default run-all step",
    )


def validate(root: Path) -> None:
    require((root / "Cargo.toml").is_file(), f"not a repository root: {root}")
    visible_file_count, markdown_link_count = validate_publication_hygiene(root)
    validate_third_party_attribution(root)
    postgres_identifier_count, postgres_identifier_max_bytes = (
        validate_postgres_identifier_lengths(root / "migrations")
    )
    broker_secret_prefix, broker_secret_length = validate_broker_secret_name_contract(root)
    json_count = validate_json_documents(root)
    scenario_count = validate_corpus(root)
    reason_count = validate_reason_codes(root)
    array_count = validate_cddl_rust_array_contract(root)
    validate_k8s_runner_patch_handoff(root)
    docker_secret_pattern_count = validate_docker_secret_exclusions(root)
    validate_postgres_upgrade_reset_guard(root)
    validate_tla_ci_separation(root)
    print(
        "PASS publication_hygiene "
        f"git_visible_files={visible_file_count} local_markdown_links={markdown_link_count}"
    )
    print("PASS third_party_attribution")
    print(
        "PASS postgres_identifier_lengths "
        f"identifiers={postgres_identifier_count} max_bytes={postgres_identifier_max_bytes}"
    )
    print(
        "PASS broker_secret_name_contract "
        f"prefix={broker_secret_prefix} bytes={broker_secret_length}"
    )
    print(f"PASS json_syntax_and_duplicate_keys documents={json_count}")
    print(f"PASS corpus_index scenarios={scenario_count}")
    print(f"PASS reason_registry codes={reason_count}")
    print(f"PASS cddl_rust_array_contract arrays={array_count}")
    print("PASS k8s_runner_single_patch_handoff")
    print(f"PASS docker_secret_exclusions patterns={docker_secret_pattern_count}")
    print("PASS postgres_v14_destructive_reset_guard")
    print("PASS tla_smoke_exhaustive_ci_separation")
    print("BOUNDARY static contract validation only; no scenario was executed")


def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument(
        "--root",
        type=Path,
        default=Path(__file__).resolve().parent.parent,
        help="repository root (defaults to parent of scripts)",
    )
    args = parser.parse_args()
    try:
        validate(args.root.resolve())
    except (ValidationError, OSError, UnicodeError) as error:
        print(f"FAIL repository_validation: {error}", file=sys.stderr)
        return 1
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
