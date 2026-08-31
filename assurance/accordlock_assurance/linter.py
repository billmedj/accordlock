"""Fail-closed validation of the AccordLock assurance manifest."""

from __future__ import annotations

from dataclasses import dataclass
import json
from pathlib import Path, PurePosixPath
import re
from typing import Any


MAX_MANIFEST_BYTES = 1_048_576
CLAIM_ID_RE = re.compile(r"^[a-z0-9]+(?:[._-][a-z0-9]+)*$")
LEAN_DECL_RE = re.compile(
    r"(?m)^\s*(?:theorem|lemma)\s+([A-Za-z_][A-Za-z0-9_'.]*)\b"
)
TLA_DEF_RE = re.compile(r"(?m)^\s*([A-Za-z_][A-Za-z0-9_]*)\s*==")
RUST_TEST_RE = re.compile(
    r"#\s*\[\s*(?:(?:tokio|async_std)::)?test(?:\s*\([^\]]*\))?\s*\]"
    r"(?:\s*#\s*\[[^\]]+\])*"
    r"\s*(?:pub(?:\([^)]*\))?\s+)?(?:async\s+)?fn\s+"
    r"([A-Za-z_][A-Za-z0-9_]*)\b",
    re.MULTILINE,
)

TOP_LEVEL_KEYS = {"schema_version", "metadata", "claims"}
METADATA_KEYS = {"name", "purpose", "assurance_levels", "source_versions"}
CLAIM_KEYS = {
    "id",
    "title",
    "statement",
    "scope",
    "lean",
    "tla",
    "runtime",
    "tests",
    "limitations",
}
LEAN_KEYS = {"path", "theorems"}
TLA_KEYS = {"model", "config", "invariants"}
RUNTIME_KEYS = {"path", "description"}
TEST_KEYS = {"path", "name"}
SOURCE_VERSION_KEYS = {"name", "path", "constant", "expected", "documents"}


class ManifestLoadError(RuntimeError):
    """Raised when the manifest cannot be safely loaded."""


def _unique_json_object(pairs: list[tuple[str, Any]]) -> dict[str, Any]:
    result: dict[str, Any] = {}
    for key, value in pairs:
        if key in result:
            raise ValueError(f"duplicate key: {key!r}")
        result[key] = value
    return result


@dataclass(frozen=True, order=True)
class Finding:
    code: str
    location: str
    message: str

    def to_dict(self) -> dict[str, str]:
        return {
            "code": self.code,
            "location": self.location,
            "message": self.message,
        }


@dataclass(frozen=True)
class VerificationReport:
    claims_checked: int
    references_checked: int
    findings: tuple[Finding, ...]

    @property
    def ok(self) -> bool:
        return not self.findings

    def to_dict(self) -> dict[str, Any]:
        return {
            "schema_version": 1,
            "ok": self.ok,
            "claims_checked": self.claims_checked,
            "references_checked": self.references_checked,
            "findings": [finding.to_dict() for finding in self.findings],
        }


class _Verifier:
    def __init__(self, root: Path, manifest_path: Path) -> None:
        self.root = root.resolve()
        self.manifest_path = manifest_path.resolve()
        self.package_root = self.manifest_path.parent
        self.findings: list[Finding] = []
        self.references_checked = 0
        self._text_cache: dict[Path, str] = {}

    def add(self, code: str, location: str, message: str) -> None:
        self.findings.append(Finding(code, location, message))

    def expect_mapping(
        self, value: Any, location: str, allowed: set[str], required: set[str]
    ) -> dict[str, Any] | None:
        if not isinstance(value, dict):
            self.add("schema.type", location, "expected a mapping")
            return None
        non_string = [key for key in value if not isinstance(key, str)]
        if non_string:
            self.add("schema.key_type", location, "all keys must be strings")
            return None
        unknown = sorted(set(value) - allowed)
        missing = sorted(required - set(value))
        if unknown:
            self.add("schema.unknown_key", location, f"unknown keys: {unknown}")
        if missing:
            self.add("schema.missing_key", location, f"missing keys: {missing}")
        return value

    def expect_string(self, value: Any, location: str) -> str | None:
        if not isinstance(value, str) or not value.strip():
            self.add("schema.string", location, "expected a non-empty string")
            return None
        if value != value.strip():
            self.add("schema.whitespace", location, "leading or trailing whitespace is forbidden")
            return None
        return value

    def expect_string_list(self, value: Any, location: str) -> list[str] | None:
        if not isinstance(value, list) or not value:
            self.add("schema.list", location, "expected a non-empty list")
            return None
        result: list[str] = []
        for index, item in enumerate(value):
            text = self.expect_string(item, f"{location}[{index}]")
            if text is not None:
                result.append(text)
        if len(result) != len(set(result)):
            self.add("schema.duplicate", location, "duplicate values are forbidden")
        return result

    def expect_list(self, value: Any, location: str, *, allow_empty: bool = False) -> list[Any] | None:
        if not isinstance(value, list) or (not allow_empty and not value):
            qualifier = "a list" if allow_empty else "a non-empty list"
            self.add("schema.list", location, f"expected {qualifier}")
            return None
        return value

    def resolve_file(self, raw: Any, location: str, suffix: str) -> Path | None:
        value = self.expect_string(raw, location)
        if value is None:
            return None
        if "\\" in value:
            self.add("path.separator", location, "use forward slashes in repository paths")
            return None
        path = PurePosixPath(value)
        if path.is_absolute() or any(part in {"", ".", ".."} for part in path.parts):
            self.add("path.unsafe", location, "path must be a normalized repository-relative path")
            return None
        if path.suffix != suffix:
            self.add("path.suffix", location, f"expected a {suffix} file")
            return None
        candidate = self.root.joinpath(*path.parts).resolve()
        try:
            candidate.relative_to(self.root)
        except ValueError:
            self.add("path.escape", location, "path escapes the repository root")
            return None
        if not candidate.is_file():
            self.add("path.missing", location, f"file does not exist: {value}")
            return None
        self.references_checked += 1
        return candidate

    def resolve_package_file(self, raw: Any, location: str) -> Path | None:
        value = self.expect_string(raw, location)
        if value is None:
            return None
        if "\\" in value:
            self.add("path.separator", location, "use forward slashes in package paths")
            return None
        path = PurePosixPath(value)
        if path.is_absolute() or any(part in {"", ".", ".."} for part in path.parts):
            self.add("path.unsafe", location, "path must be normalized and package-relative")
            return None
        candidate = self.package_root.joinpath(*path.parts).resolve()
        try:
            candidate.relative_to(self.package_root)
        except ValueError:
            self.add("path.escape", location, "path escapes the assurance package")
            return None
        if not candidate.is_file():
            self.add("path.missing", location, f"package file does not exist: {value}")
            return None
        self.references_checked += 1
        return candidate

    def read_text(self, path: Path, location: str) -> str | None:
        if path in self._text_cache:
            return self._text_cache[path]
        try:
            text = path.read_text(encoding="utf-8")
        except (OSError, UnicodeError) as error:
            self.add("path.read", location, f"cannot read UTF-8 source: {error}")
            return None
        self._text_cache[path] = text
        return text

    def verify_lean(self, entries: Any, claim_location: str) -> None:
        items = self.expect_list(entries, f"{claim_location}.lean")
        if items is None:
            return
        for index, raw_entry in enumerate(items):
            location = f"{claim_location}.lean[{index}]"
            entry = self.expect_mapping(raw_entry, location, LEAN_KEYS, LEAN_KEYS)
            if entry is None:
                continue
            path = self.resolve_file(entry.get("path"), f"{location}.path", ".lean")
            theorem_names = self.expect_string_list(
                entry.get("theorems"), f"{location}.theorems"
            )
            if path is None or theorem_names is None:
                continue
            text = self.read_text(path, location)
            if text is None:
                continue
            declarations = set(LEAN_DECL_RE.findall(_strip_lean_comments(text)))
            for theorem in theorem_names:
                self.references_checked += 1
                if theorem not in declarations:
                    self.add(
                        "lean.theorem_missing",
                        f"{location}.theorems",
                        f"theorem or lemma is not declared in {entry['path']}: {theorem}",
                    )

    def verify_tla(self, entries: Any, claim_location: str) -> None:
        items = self.expect_list(entries, f"{claim_location}.tla", allow_empty=True)
        if items is None:
            return
        for index, raw_entry in enumerate(items):
            location = f"{claim_location}.tla[{index}]"
            entry = self.expect_mapping(raw_entry, location, TLA_KEYS, TLA_KEYS)
            if entry is None:
                continue
            model = self.resolve_file(entry.get("model"), f"{location}.model", ".tla")
            config = self.resolve_file(entry.get("config"), f"{location}.config", ".cfg")
            invariants = self.expect_string_list(
                entry.get("invariants"), f"{location}.invariants"
            )
            if model is None or config is None or invariants is None:
                continue
            model_text = self.read_text(model, location)
            config_text = self.read_text(config, location)
            if model_text is None or config_text is None:
                continue
            definitions = set(TLA_DEF_RE.findall(_strip_tla_comments(model_text)))
            selected = _configured_invariants(_strip_tla_comments(config_text))
            for invariant in invariants:
                self.references_checked += 1
                if invariant not in definitions:
                    self.add(
                        "tla.invariant_missing",
                        f"{location}.invariants",
                        f"operator is not defined in {entry['model']}: {invariant}",
                    )
                if invariant not in selected:
                    self.add(
                        "tla.invariant_unconfigured",
                        f"{location}.invariants",
                        f"invariant is not selected by {entry['config']}: {invariant}",
                    )

    def verify_runtime(self, entries: Any, claim_location: str) -> None:
        items = self.expect_list(entries, f"{claim_location}.runtime")
        if items is None:
            return
        seen: set[str] = set()
        for index, raw_entry in enumerate(items):
            location = f"{claim_location}.runtime[{index}]"
            entry = self.expect_mapping(raw_entry, location, RUNTIME_KEYS, RUNTIME_KEYS)
            if entry is None:
                continue
            path_value = entry.get("path")
            self.resolve_file(path_value, f"{location}.path", ".rs")
            self.expect_string(entry.get("description"), f"{location}.description")
            if isinstance(path_value, str):
                if path_value in seen:
                    self.add("runtime.duplicate", location, f"duplicate runtime path: {path_value}")
                seen.add(path_value)

    def verify_tests(self, entries: Any, claim_location: str) -> None:
        items = self.expect_list(entries, f"{claim_location}.tests")
        if items is None:
            return
        seen: set[tuple[str, str]] = set()
        for index, raw_entry in enumerate(items):
            location = f"{claim_location}.tests[{index}]"
            entry = self.expect_mapping(raw_entry, location, TEST_KEYS, TEST_KEYS)
            if entry is None:
                continue
            path = self.resolve_file(entry.get("path"), f"{location}.path", ".rs")
            name = self.expect_string(entry.get("name"), f"{location}.name")
            if path is None or name is None:
                continue
            pair = (str(entry.get("path")), name)
            if pair in seen:
                self.add("rust_test.duplicate", location, f"duplicate test reference: {name}")
            seen.add(pair)
            text = self.read_text(path, location)
            if text is None:
                continue
            self.references_checked += 1
            discovered = set(RUST_TEST_RE.findall(_strip_rust_comments(text)))
            if name not in discovered:
                self.add(
                    "rust_test.missing",
                    f"{location}.name",
                    f"decorated Rust test is not declared in {entry['path']}: {name}",
                )

    def verify_source_versions(self, entries: Any, location: str) -> None:
        items = self.expect_list(entries, location)
        if items is None:
            return
        names: set[str] = set()
        for index, raw_entry in enumerate(items):
            item_location = f"{location}[{index}]"
            entry = self.expect_mapping(
                raw_entry,
                item_location,
                SOURCE_VERSION_KEYS,
                SOURCE_VERSION_KEYS,
            )
            if entry is None:
                continue
            name = self.expect_string(entry.get("name"), f"{item_location}.name")
            constant = self.expect_string(
                entry.get("constant"), f"{item_location}.constant"
            )
            expected = entry.get("expected")
            if not isinstance(expected, int) or isinstance(expected, bool) or expected < 0:
                self.add(
                    "schema.integer",
                    f"{item_location}.expected",
                    "expected a non-negative integer",
                )
                expected = None
            documents = self.expect_string_list(
                entry.get("documents"), f"{item_location}.documents"
            )
            path = self.resolve_file(entry.get("path"), f"{item_location}.path", ".rs")
            if name is not None:
                if name in names:
                    self.add("source_version.duplicate", item_location, f"duplicate name: {name}")
                names.add(name)
            if path is not None and constant is not None and expected is not None:
                text = self.read_text(path, item_location)
                if text is not None:
                    pattern = re.compile(
                        rf"(?m)^\s*(?:pub\s+)?const\s+{re.escape(constant)}\s*:[^=]+="
                        rf"\s*([0-9]+)\s*;"
                    )
                    match = pattern.search(_strip_rust_comments(text))
                    self.references_checked += 1
                    if match is None:
                        self.add(
                            "source_version.constant_missing",
                            f"{item_location}.constant",
                            f"integer constant is not declared in {entry['path']}: {constant}",
                        )
                    elif int(match.group(1)) != expected:
                        self.add(
                            "source_version.stale_expected",
                            f"{item_location}.expected",
                            f"manifest expects {expected}, source declares {match.group(1)}",
                        )
            if name is None or expected is None or documents is None:
                continue
            wording = re.compile(
                rf"(?i)\b{re.escape(name)}(?:\s+schema)?\s+v?([0-9]+)\b"
            )
            for document_index, raw_document in enumerate(documents):
                document_location = f"{item_location}.documents[{document_index}]"
                document = self.resolve_package_file(raw_document, document_location)
                if document is None:
                    continue
                try:
                    document_text = document.read_text(encoding="utf-8")
                except (OSError, UnicodeError) as error:
                    self.add("path.read", document_location, f"cannot read UTF-8 source: {error}")
                    continue
                for match in wording.finditer(document_text):
                    self.references_checked += 1
                    observed = int(match.group(1))
                    if observed != expected:
                        self.add(
                            "source_version.stale_wording",
                            document_location,
                            f"{name} wording says v{observed}; source contract is v{expected}",
                        )

    def verify_claim(self, raw_claim: Any, index: int, seen_ids: set[str]) -> None:
        location = f"claims[{index}]"
        claim = self.expect_mapping(raw_claim, location, CLAIM_KEYS, CLAIM_KEYS)
        if claim is None:
            return
        claim_id = self.expect_string(claim.get("id"), f"{location}.id")
        if claim_id is not None:
            if not CLAIM_ID_RE.fullmatch(claim_id):
                self.add("claim.id", f"{location}.id", "claim id is not canonical")
            if claim_id in seen_ids:
                self.add("claim.duplicate", f"{location}.id", f"duplicate claim id: {claim_id}")
            seen_ids.add(claim_id)
            location = f"claims[{claim_id}]"
        for key in ("title", "statement", "scope"):
            self.expect_string(claim.get(key), f"{location}.{key}")
        self.expect_string_list(claim.get("limitations"), f"{location}.limitations")
        self.verify_lean(claim.get("lean"), location)
        self.verify_tla(claim.get("tla"), location)
        self.verify_runtime(claim.get("runtime"), location)
        self.verify_tests(claim.get("tests"), location)


def _strip_lean_comments(text: str) -> str:
    output: list[str] = []
    index = 0
    block_depth = 0
    in_string = False
    while index < len(text):
        pair = text[index : index + 2]
        if block_depth:
            if pair == "/-":
                block_depth += 1
                output.extend("  ")
                index += 2
            elif pair == "-/":
                block_depth -= 1
                output.extend("  ")
                index += 2
            else:
                output.append("\n" if text[index] == "\n" else " ")
                index += 1
            continue
        if not in_string and pair == "/-":
            block_depth = 1
            output.extend("  ")
            index += 2
            continue
        if not in_string and pair == "--":
            end = text.find("\n", index)
            if end == -1:
                output.extend(" " * (len(text) - index))
                break
            output.extend(" " * (end - index))
            index = end
            continue
        char = text[index]
        if char == '"' and (index == 0 or text[index - 1] != "\\"):
            in_string = not in_string
        output.append(char)
        index += 1
    return "".join(output)


def _strip_tla_comments(text: str) -> str:
    text = re.sub(r"\(\*.*?\*\)", lambda match: "\n" * match.group(0).count("\n"), text, flags=re.DOTALL)
    return re.sub(r"\\\*[^\n]*", "", text)


def _strip_rust_comments(text: str) -> str:
    text = re.sub(r"/\*.*?\*/", lambda match: "\n" * match.group(0).count("\n"), text, flags=re.DOTALL)
    return re.sub(r"//[^\n]*", "", text)


def _configured_invariants(config_text: str) -> set[str]:
    directives = {
        "SPECIFICATION",
        "CONSTANT",
        "CONSTANTS",
        "PROPERTY",
        "PROPERTIES",
        "CONSTRAINT",
        "CONSTRAINTS",
        "ACTION_CONSTRAINT",
        "ACTION_CONSTRAINTS",
        "CHECK_DEADLOCK",
        "SYMMETRY",
        "VIEW",
        "POSTCONDITION",
        "ALIAS",
    }
    selected: set[str] = set()
    collecting = False
    for raw_line in config_text.splitlines():
        line = raw_line.strip()
        if not line:
            continue
        parts = line.split()
        head = parts[0]
        if head in {"INVARIANT", "INVARIANTS"}:
            collecting = True
            selected.update(
                part for part in parts[1:] if re.fullmatch(r"[A-Za-z_][A-Za-z0-9_]*", part)
            )
            continue
        if head in directives:
            collecting = False
            continue
        if collecting:
            for part in parts:
                if re.fullmatch(r"[A-Za-z_][A-Za-z0-9_]*", part):
                    selected.add(part)
    return selected


def _load_manifest(path: Path) -> Any:
    try:
        size = path.stat().st_size
    except OSError as error:
        raise ManifestLoadError(f"cannot stat manifest: {error}") from error
    if size > MAX_MANIFEST_BYTES:
        raise ManifestLoadError(
            f"manifest is {size} bytes; maximum is {MAX_MANIFEST_BYTES} bytes"
        )
    try:
        source = path.read_text(encoding="utf-8")
    except (OSError, UnicodeError) as error:
        raise ManifestLoadError(f"cannot read UTF-8 manifest: {error}") from error
    try:
        # JSON is a strict subset of YAML 1.2. Keeping claims.yaml in this
        # subset gives deterministic, dependency-free parsing in every Python
        # environment while remaining consumable by standard YAML tooling.
        return json.loads(source, object_pairs_hook=_unique_json_object)
    except (json.JSONDecodeError, ValueError) as error:
        raise ManifestLoadError(f"invalid JSON-compatible YAML: {error}") from error


def verify_manifest(manifest_path: Path | str, root: Path | str) -> VerificationReport:
    """Validate manifest structure and every source-level traceability link."""

    manifest_path = Path(manifest_path).resolve()
    root = Path(root).resolve()
    manifest = _load_manifest(manifest_path)
    verifier = _Verifier(root, manifest_path)

    top = verifier.expect_mapping(
        manifest,
        "manifest",
        TOP_LEVEL_KEYS,
        TOP_LEVEL_KEYS,
    )
    claims_checked = 0
    if top is not None:
        if top.get("schema_version") != 1:
            verifier.add("schema.version", "manifest.schema_version", "expected schema version 1")
        metadata = verifier.expect_mapping(
            top.get("metadata"),
            "manifest.metadata",
            METADATA_KEYS,
            METADATA_KEYS,
        )
        if metadata is not None:
            verifier.expect_string(metadata.get("name"), "manifest.metadata.name")
            verifier.expect_string(metadata.get("purpose"), "manifest.metadata.purpose")
            verifier.expect_string_list(
                metadata.get("assurance_levels"),
                "manifest.metadata.assurance_levels",
            )
            verifier.verify_source_versions(
                metadata.get("source_versions"),
                "manifest.metadata.source_versions",
            )
        claims = verifier.expect_list(top.get("claims"), "manifest.claims")
        if claims is not None:
            claims_checked = len(claims)
            seen_ids: set[str] = set()
            for index, claim in enumerate(claims):
                verifier.verify_claim(claim, index, seen_ids)

    return VerificationReport(
        claims_checked=claims_checked,
        references_checked=verifier.references_checked,
        findings=tuple(sorted(verifier.findings)),
    )
