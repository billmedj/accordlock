from __future__ import annotations

import argparse
import hashlib
import re
import subprocess
from pathlib import Path
from typing import NamedTuple


MANIFEST_NAME = "SOURCE_MANIFEST.sha256"
LINE_PATTERN = re.compile(r"([0-9a-f]{64})  ([^\\\r\n]+)")
RUST_INCLUDE_CALL = re.compile(r"\binclude(?:_str|_bytes)?!\s*\(")
RUST_INCLUDE_LITERAL = re.compile(
    r'\binclude(?:_str|_bytes)?!\s*\(\s*"([^"\r\n]+)"\s*\)'
)
RUST_PATH_ATTRIBUTE = re.compile(r'#\s*\[\s*path\s*=\s*"([^"\r\n]+)"\s*\]')


class ManifestError(RuntimeError):
    pass


class DepInfoSummary(NamedTuple):
    dep_info_files: int
    repository_inputs: int
    generated_inputs: int


def repository_paths(repository: Path, git: str) -> list[str]:
    repository = repository.resolve()
    if (repository / ".git").exists():
        completed = subprocess.run(
            [git, "ls-files", "-z", "--cached", "--others", "--exclude-standard"],
            cwd=repository,
            check=False,
            capture_output=True,
            timeout=60,
        )
        if completed.returncode != 0:
            raise ManifestError(
                f"git ls-files failed with {completed.returncode}: "
                + completed.stderr.decode("utf-8", errors="replace").strip()
            )
        try:
            values = completed.stdout.decode("utf-8", errors="strict").split("\0")
        except UnicodeDecodeError as error:
            raise ManifestError("repository paths are not UTF-8") from error
    else:
        excluded_roots = {
            ".git",
            ".lake",
            ".local",
            "__pycache__",
            "node_modules",
            "target",
        }
        values = [
            path.relative_to(repository).as_posix()
            for path in repository.rglob("*")
            if path.is_file()
            and not any(
                part in excluded_roots or part.startswith(".tmp")
                for part in path.relative_to(repository).parts
            )
            and path.relative_to(repository).parts[:2] != ("models", "states")
        ]
    paths = [value for value in values if value and value != MANIFEST_NAME]
    if paths != sorted(paths) or len(paths) != len(set(paths)):
        paths = sorted(set(paths))
    if not paths:
        raise ManifestError("repository source set is empty")
    return paths


def build_entries(repository: Path, paths: list[str]) -> list[tuple[str, str]]:
    repository = repository.resolve()
    entries: list[tuple[str, str]] = []
    for relative in paths:
        if Path(relative).is_absolute() or relative.startswith("../"):
            raise ManifestError(f"unsafe repository path: {relative}")
        candidate = repository / relative
        resolved = candidate.resolve()
        if candidate.is_symlink() or not resolved.is_relative_to(repository):
            raise ManifestError(f"source path escapes repository: {relative}")
        if not candidate.is_file():
            raise ManifestError(f"source path is not a regular file: {relative}")
        digest = hashlib.sha256(candidate.read_bytes()).hexdigest()
        entries.append((relative.replace("\\", "/"), digest))
    entries.sort()
    return entries


def validate_rust_compiler_inputs(repository: Path, paths: list[str]) -> int:
    repository = repository.resolve()
    visible = {path.replace("\\", "/") for path in paths}
    validated = 0
    for relative in sorted(path for path in visible if path.endswith(".rs")):
        source_path = repository / relative
        source = source_path.read_text(encoding="utf-8")
        literal_includes = RUST_INCLUDE_LITERAL.findall(source)
        if len(RUST_INCLUDE_CALL.findall(source)) != len(literal_includes):
            raise ManifestError(
                f"Rust source uses a non-literal include macro: {relative}"
            )
        referenced = literal_includes + RUST_PATH_ATTRIBUTE.findall(source)
        for reference in referenced:
            resolved = (source_path.parent / reference).resolve()
            if not resolved.is_relative_to(repository) or not resolved.is_file():
                raise ManifestError(
                    f"Rust compiler input escapes or is missing: {relative}: {reference}"
                )
            normalized = resolved.relative_to(repository).as_posix()
            if normalized not in visible:
                raise ManifestError(
                    f"Rust compiler input is ignored or absent from manifest: {normalized}"
                )
            validated += 1
    return validated


def _makefile_words(value: str) -> list[str]:
    """Splits one rustc makefile dependency list without eating Windows slashes."""
    words: list[str] = []
    current: list[str] = []
    index = 0
    while index < len(value):
        character = value[index]
        if character == "\\" and index + 1 < len(value):
            following = value[index + 1]
            if following in " \t#":
                current.append(following)
                index += 2
                continue
        if character.isspace():
            if current:
                words.append("".join(current))
                current = []
        else:
            current.append(character)
        index += 1
    if current:
        words.append("".join(current))
    return words


def parse_dep_info(text: str) -> list[str]:
    """Returns dependency paths from rustc's makefile-style dep-info."""
    logical = text.replace("\\\r\n", "").replace("\\\n", "")
    dependencies: list[str] = []
    for line in logical.splitlines():
        separator = line.find(": ")
        if separator < 0:
            continue
        dependencies.extend(_makefile_words(line[separator + 2 :]))
    return dependencies


def validate_rust_dep_info(
    repository: Path, paths: list[str], dep_info_root: Path
) -> DepInfoSummary:
    """Checks the actual local compiler inputs recorded by rustc dep-info files."""
    repository = repository.resolve()
    dep_info_root = dep_info_root.resolve()
    if not dep_info_root.is_dir():
        raise ManifestError(f"rust dep-info root is missing: {dep_info_root}")
    visible = {path.replace("\\", "/") for path in paths}
    dep_info_files = sorted(dep_info_root.rglob("*.d"))
    if not dep_info_files:
        raise ManifestError(f"no rust dep-info files found under: {dep_info_root}")

    repository_inputs: set[str] = set()
    generated_inputs: set[str] = set()
    for dep_info in dep_info_files:
        try:
            dependencies = parse_dep_info(dep_info.read_text(encoding="utf-8"))
        except UnicodeDecodeError as error:
            raise ManifestError(f"rust dep-info is not UTF-8: {dep_info}") from error
        for dependency in dependencies:
            candidate = Path(dependency)
            if not candidate.is_absolute():
                candidate = repository / candidate
            resolved = candidate.resolve()
            if not resolved.exists():
                # Old dep-info may survive an incremental build after a source was
                # deleted. Existing compiler inputs remain fail-closed below.
                continue
            if not resolved.is_file() or not resolved.is_relative_to(repository):
                continue
            relative = resolved.relative_to(repository).as_posix()
            if resolved.is_relative_to(dep_info_root):
                generated_inputs.add(relative)
                continue
            if relative not in visible:
                raise ManifestError(
                    f"rustc read a repository input absent from the source manifest: {relative}"
                )
            repository_inputs.add(relative)

    if not repository_inputs:
        raise ManifestError("rust dep-info contains no repository compiler inputs")
    return DepInfoSummary(
        dep_info_files=len(dep_info_files),
        repository_inputs=len(repository_inputs),
        generated_inputs=len(generated_inputs),
    )


def serialize(entries: list[tuple[str, str]]) -> str:
    return "".join(f"{digest}  {relative}\n" for relative, digest in entries)


def parse_manifest(text: str) -> list[tuple[str, str]]:
    entries: list[tuple[str, str]] = []
    for number, line in enumerate(text.splitlines(), start=1):
        match = LINE_PATTERN.fullmatch(line)
        if match is None:
            raise ManifestError(f"malformed manifest line {number}")
        digest, relative = match.groups()
        entries.append((relative, digest))
    paths = [relative for relative, _digest in entries]
    if paths != sorted(paths) or len(paths) != len(set(paths)):
        raise ManifestError("manifest paths are duplicated or not sorted")
    return entries


def validate(repository: Path, git: str) -> int:
    paths = repository_paths(repository, git)
    validate_rust_compiler_inputs(repository, paths)
    expected = build_entries(repository, paths)
    manifest_path = repository / MANIFEST_NAME
    actual = parse_manifest(manifest_path.read_text(encoding="utf-8"))
    if actual != expected:
        actual_map = dict(actual)
        expected_map = dict(expected)
        missing = sorted(set(expected_map) - set(actual_map))
        extra = sorted(set(actual_map) - set(expected_map))
        changed = sorted(
            path
            for path in set(actual_map) & set(expected_map)
            if actual_map[path] != expected_map[path]
        )
        raise ManifestError(
            f"source manifest drift: missing={missing} extra={extra} changed={changed}"
        )
    return len(expected)


def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument(
        "--repository", type=Path, default=Path(__file__).resolve().parents[1]
    )
    parser.add_argument("--git", default="git")
    parser.add_argument("--write", action="store_true")
    parser.add_argument(
        "--dep-info-root",
        type=Path,
        help="also verify actual repository inputs recorded by rustc *.d files",
    )
    args = parser.parse_args()
    repository = args.repository.resolve()
    try:
        if args.write and args.dep_info_root is not None:
            raise ManifestError("--write and --dep-info-root are separate operations")
        paths = repository_paths(repository, args.git)
        validate_rust_compiler_inputs(repository, paths)
        entries = build_entries(repository, paths)
        if args.write:
            (repository / MANIFEST_NAME).write_text(
                serialize(entries), encoding="utf-8", newline="\n"
            )
            print(f"PASS source_manifest_written files={len(entries)}")
        else:
            count = validate(repository, args.git)
            print(f"PASS source_manifest_verified files={count}")
            if args.dep_info_root is not None:
                dep_info_root = args.dep_info_root
                if not dep_info_root.is_absolute():
                    dep_info_root = repository / dep_info_root
                summary = validate_rust_dep_info(repository, paths, dep_info_root)
                print(
                    "PASS rust_dep_info_verified "
                    f"dep_info_files={summary.dep_info_files} "
                    f"repository_inputs={summary.repository_inputs} "
                    f"generated_inputs={summary.generated_inputs}"
                )
    except (ManifestError, OSError, subprocess.SubprocessError) as error:
        print(f"FAIL source_manifest {error}")
        return 1
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
