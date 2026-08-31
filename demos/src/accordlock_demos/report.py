from __future__ import annotations

import json
import os
import tempfile
from pathlib import Path
from typing import Any


def render_markdown(report: dict[str, Any]) -> str:
    status = report.get("status", "UNKNOWN")
    lines = [
        "# AccordLock provider-free adversarial demonstration",
        "",
        f"**Result:** {status}",
        "",
        "This report records decisions produced by AccordLock's native CLI and trusted local runtime. It uses no model provider, account, or oracle baseline.",
        "",
        "## Cases",
        "",
        "| Case | Result | Observed decision |",
        "|---|---:|---|",
    ]
    for case in report.get("cases", []):
        observed = case.get("observed", {})
        decision = observed.get("reason_code") or observed.get("identical_retry")
        if not decision and isinstance(observed.get("replay_attempt"), dict):
            decision = observed["replay_attempt"].get("reason")
        if not decision and isinstance(observed.get("consumption"), dict):
            decision = observed["consumption"].get("reason")
        lines.append(
            f"| {_cell(case.get('claim'))} | {_cell(case.get('status'))} | {_cell(decision or 'See evidence')} |"
        )
    lines.extend(["", "## Evidence", ""])
    for case in report.get("cases", []):
        lines.extend(
            [
                f"### {case.get('case_id', 'unknown')}",
                "",
                str(case.get("interpretation", "")),
                "",
                "```json",
                json.dumps(case.get("observed", {}), indent=2, ensure_ascii=False, sort_keys=True),
                "```",
                "",
            ]
        )
    lines.extend(["## Execution profile", "", "```json"])
    lines.append(
        json.dumps(report.get("execution_profile", {}), indent=2, ensure_ascii=False, sort_keys=True)
    )
    lines.extend(["```", "", "## Limitations", ""])
    for limitation in report.get("limitations", []):
        lines.append(f"- {limitation}")
    lines.append("")
    return "\n".join(lines)


def write_reports(report: dict[str, Any], output_directory: Path) -> tuple[Path, Path]:
    output_directory.mkdir(parents=True, exist_ok=True)
    json_path = output_directory / "adversarial-demo.json"
    markdown_path = output_directory / "adversarial-demo.md"
    _atomic_write(
        json_path,
        json.dumps(report, indent=2, ensure_ascii=False, sort_keys=True) + "\n",
    )
    _atomic_write(markdown_path, render_markdown(report))
    return json_path, markdown_path


def _atomic_write(path: Path, content: str) -> None:
    descriptor, temporary = tempfile.mkstemp(prefix=f".{path.name}.", dir=path.parent)
    temporary_path = Path(temporary)
    try:
        with os.fdopen(descriptor, "w", encoding="utf-8", newline="\n") as stream:
            stream.write(content)
            stream.flush()
            os.fsync(stream.fileno())
        os.replace(temporary_path, path)
    except Exception:
        temporary_path.unlink(missing_ok=True)
        raise


def _cell(value: object) -> str:
    return str(value if value is not None else "").replace("|", "\\|").replace("\n", " ")
