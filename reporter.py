"""Reporting helpers for secrets watcher."""
from __future__ import annotations

from dataclasses import dataclass
from datetime import datetime
from pathlib import Path
from typing import Iterable, Sequence
import json


@dataclass(frozen=True)
class Finding:
    scanner: str
    org: str
    repo: str
    rule: str
    description: str
    location: str
    commit: str
    url: str | None
    raw: dict

    def key(self) -> tuple[str, str, str, str, str]:
        return (self.scanner, self.org, self.repo, self.rule, self.location)


class Reporter:
    def __init__(self, report_path: Path) -> None:
        self._report_path = report_path
        self._report_path.parent.mkdir(parents=True, exist_ok=True)

    def write_markdown(self, findings: Sequence[Finding], generated_at: datetime) -> Path:
        content = self._render_markdown(findings, generated_at)
        self._report_path.write_text(content, encoding="utf-8")
        return self._report_path

    def write_raw_jsonl(self, findings: Iterable[Finding], run_id: str, raw_dir: Path) -> Path:
        raw_dir.mkdir(parents=True, exist_ok=True)
        destination = raw_dir / f"{run_id}_findings.jsonl"
        with destination.open("w", encoding="utf-8") as handle:
            for finding in findings:
                payload = {
                    "scanner": finding.scanner,
                    "org": finding.org,
                    "repo": finding.repo,
                    "rule": finding.rule,
                    "location": finding.location,
                    "commit": finding.commit,
                    "url": finding.url,
                    "raw": finding.raw,
                }
                handle.write(json.dumps(payload, ensure_ascii=False))
                handle.write("\n")
        return destination

    def _render_markdown(self, findings: Sequence[Finding], generated_at: datetime) -> str:
        header = [
            "# Secrets Scan Report",
            f"Generated: {generated_at.isoformat()}",
            "",
            f"Total findings: {len(findings)}",
            "",
        ]
        lines = list(header)
        if findings:
            lines.extend(self._build_table(findings))
            lines.append("")
            lines.extend(self._build_details(findings))
        else:
            lines.append("No secrets detected by either scanner.")
        return "\n".join(lines).rstrip() + "\n"

    def _build_table(self, findings: Sequence[Finding]) -> list[str]:
        rows = [
            "| Scanner | Org | Repo | Rule | Location | Commit |",
            "| --- | --- | --- | --- | --- | --- |",
        ]
        for finding in sorted(findings, key=lambda f: (f.org, f.repo, f.scanner, f.rule, f.location)):
            commit = finding.commit[:10] if finding.commit else "?"
            rows.append(
                f"| {finding.scanner} | {finding.org} | {finding.repo} | {finding.rule} | {finding.location} | {commit} |"
            )
        return rows

    def _build_details(self, findings: Sequence[Finding]) -> list[str]:
        output: list[str] = ["## Finding Details", ""]
        for finding in sorted(findings, key=lambda f: (f.org, f.repo, f.scanner, f.rule, f.location)):
            output.append(f"### {finding.rule} - {finding.repo} ({finding.scanner})")
            output.append(f"- Org: {finding.org}")
            output.append(f"- Location: {finding.location}")
            if finding.commit:
                output.append(f"- Commit: {finding.commit}")
            if finding.url:
                output.append(f"- URL: {finding.url}")
            if finding.description:
                output.append(f"- Detail: {finding.description}")
            output.append("")
        return output


def dedupe_findings(findings: Iterable[Finding]) -> list[Finding]:
    seen: dict[tuple[str, str, str, str, str], Finding] = {}
    for finding in findings:
        key = finding.key()
        if key not in seen:
            seen[key] = finding
    return list(seen.values())


