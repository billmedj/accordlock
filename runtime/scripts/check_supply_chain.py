from __future__ import annotations

import argparse
import json
import re
import subprocess
import tomllib
from pathlib import Path


CRATES_IO_SOURCE = "registry+https://github.com/rust-lang/crates.io-index"
HEX_256 = re.compile(r"[0-9a-f]{64}")


class SupplyChainError(RuntimeError):
    pass


def _metadata(repository: Path, cargo: str) -> dict[str, object]:
    completed = subprocess.run(
        [cargo, "metadata", "--locked", "--format-version", "1"],
        cwd=repository,
        check=False,
        capture_output=True,
        text=True,
        timeout=120,
    )
    if completed.returncode != 0:
        raise SupplyChainError(
            f"cargo metadata failed with {completed.returncode}: {completed.stderr.strip()}"
        )
    return json.loads(completed.stdout)


def validate(repository: Path, cargo: str) -> dict[str, object]:
    repository = repository.resolve()
    lock_path = repository / "Cargo.lock"
    lock = tomllib.loads(lock_path.read_text(encoding="utf-8"))
    metadata = _metadata(repository, cargo)
    packages = metadata.get("packages")
    workspace_members = metadata.get("workspace_members")
    if not isinstance(packages, list) or not isinstance(workspace_members, list):
        raise SupplyChainError("cargo metadata has an unexpected shape")

    workspace_member_ids = set(workspace_members)
    local_packages: set[tuple[str, str]] = set()
    external = []
    for package in packages:
        if not isinstance(package, dict):
            raise SupplyChainError("cargo metadata contains a non-object package")
        source = package.get("source")
        if source is None:
            package_id = package.get("id")
            manifest_path = package.get("manifest_path")
            if not isinstance(package_id, str) or package_id not in workspace_member_ids:
                raise SupplyChainError(
                    f"source-less package is not a workspace member: {package.get('name')} {package.get('version')}"
                )
            if not isinstance(manifest_path, str):
                raise SupplyChainError(
                    f"workspace package has no manifest path: {package.get('name')} {package.get('version')}"
                )
            resolved_manifest = Path(manifest_path).resolve()
            if not resolved_manifest.is_relative_to(repository):
                raise SupplyChainError(
                    f"workspace manifest escapes repository: {resolved_manifest}"
                )
            if not resolved_manifest.is_file():
                raise SupplyChainError(
                    f"workspace manifest is missing: {resolved_manifest}"
                )
            targets = package.get("targets")
            if not isinstance(targets, list) or not targets:
                raise SupplyChainError(
                    f"workspace package has no Cargo targets: {package.get('name')} {package.get('version')}"
                )
            for target in targets:
                if not isinstance(target, dict) or not isinstance(
                    target.get("src_path"), str
                ):
                    raise SupplyChainError("workspace Cargo target is malformed")
                target_path = Path(target["src_path"]).resolve()
                if not target_path.is_relative_to(repository):
                    raise SupplyChainError(
                        f"workspace Cargo target escapes repository: {target_path}"
                    )
                if not target_path.is_file():
                    raise SupplyChainError(
                        f"workspace Cargo target is missing: {target_path}"
                    )
            name = package.get("name")
            version = package.get("version")
            if not isinstance(name, str) or not isinstance(version, str):
                raise SupplyChainError("workspace package identity is malformed")
            local_packages.add((name, version))
            continue
        if source != CRATES_IO_SOURCE:
            raise SupplyChainError(
                f"non-crates.io dependency: {package.get('name')} {package.get('version')} {source}"
            )
        license_expression = package.get("license")
        if not isinstance(license_expression, str) or not license_expression.strip():
            raise SupplyChainError(
                f"dependency has no non-empty Cargo license metadata: {package.get('name')} {package.get('version')}"
            )
        external.append(package)

    lock_packages = lock.get("package")
    if not isinstance(lock_packages, list):
        raise SupplyChainError("Cargo.lock does not contain package records")
    registry_records = 0
    for package in lock_packages:
        if not isinstance(package, dict):
            raise SupplyChainError("Cargo.lock contains a non-table package")
        source = package.get("source")
        if source is None:
            name = package.get("name")
            version = package.get("version")
            if (name, version) not in local_packages:
                raise SupplyChainError(
                    f"Cargo.lock contains an unrecognized source-less package: {name} {version}"
                )
            continue
        if source != CRATES_IO_SOURCE:
            raise SupplyChainError(
                f"Cargo.lock contains a non-crates.io source: {package.get('name')} {source}"
            )
        checksum = package.get("checksum")
        if not isinstance(checksum, str) or HEX_256.fullmatch(checksum) is None:
            raise SupplyChainError(
                f"Cargo.lock checksum is missing or malformed: {package.get('name')} {package.get('version')}"
            )
        registry_records += 1

    if registry_records != len(external):
        raise SupplyChainError(
            f"Cargo.lock/metadata external-package mismatch: lock={registry_records} metadata={len(external)}"
        )

    return {
        "workspace_packages": len(workspace_members),
        "external_packages": len(external),
        "registry": CRATES_IO_SOURCE,
        "checksums_present": registry_records,
        "local_manifests_under_repository": len(local_packages),
        "missing_license_metadata": 0,
        "license_policy_evaluated": False,
    }


def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("--cargo", default="cargo")
    parser.add_argument(
        "--repository", type=Path, default=Path(__file__).resolve().parents[1]
    )
    args = parser.parse_args()
    try:
        result = validate(args.repository.resolve(), args.cargo)
    except (OSError, ValueError, SupplyChainError, subprocess.SubprocessError) as error:
        print(f"FAIL supply_chain {error}")
        return 1
    print("PASS supply_chain " + json.dumps(result, sort_keys=True, separators=(",", ":")))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
