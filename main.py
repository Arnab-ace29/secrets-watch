"""Entry point for the two-stage secrets watcher."""
from __future__ import annotations

import argparse
import json
import os
import subprocess
from dataclasses import dataclass
from datetime import datetime, timezone
from pathlib import Path
from typing import Any, Iterable
import urllib.request
import urllib.parse

import yaml

from reporter import Finding, Reporter, dedupe_findings


@dataclass
class RunContext:
    github_cfg: dict[str, Any]
    trufflehog_cfg: dict[str, Any]
    gitleaks_cfg: dict[str, Any]
    run_cfg: dict[str, Any]
    token: str | None
    log_path: Path
    history_path: Path
    state_path: Path
    report_path: Path
    raw_dir: Path


class StateTracker:
    def __init__(self, path: Path) -> None:
        self._path = path
        self._index = 0
        self._loaded = False

    def current(self) -> int:
        if not self._loaded:
            self._index = self._load()
            self._loaded = True
        return self._index

    def update(self, index: int) -> None:
        self._index = max(0, index)
        self._path.parent.mkdir(parents=True, exist_ok=True)
        self._path.write_text(f"next_org: {self._index}\n", encoding="utf-8")

    def _load(self) -> int:
        if not self._path.exists():
            return 0
        try:
            raw = self._path.read_text(encoding="utf-8").strip()
        except OSError:
            return 0
        if not raw:
            return 0
        try:
            _, value = raw.split(":", 1)
            return int(value.strip())
        except Exception:
            return 0


def parse_args() -> argparse.Namespace:
    parser = argparse.ArgumentParser(description="Run TruffleHog and Gitleaks across GitHub orgs")
    parser.add_argument("--config", default="config.yaml", help="Path to YAML configuration")
    parser.add_argument("--max-orgs", type=int, help="Limit run to N orgs starting from pointer")
    parser.add_argument("--start-index", type=int, help="Override pointer and start at org index")
    parser.add_argument("--force", action="store_true", help="Ignore state pointer and start at top")
    return parser.parse_args()


def load_config(path: Path) -> dict[str, Any]:
    try:
        data = yaml.safe_load(path.read_text(encoding="utf-8"))
    except FileNotFoundError as exc:
        raise SystemExit(f"Config file not found: {path}") from exc
    if not isinstance(data, dict):
        raise SystemExit("Config must be a mapping")
    return data


def resolve_path(base: Path, relative: str) -> Path:
    candidate = Path(relative)
    if not candidate.is_absolute():
        candidate = (base / candidate).resolve()
    return candidate


def append_log(log_path: Path, timestamp: datetime, command: list[str], stdout: str, stderr: str, returncode: int, mask_values: Iterable[str | None] = ()) -> None:
    log_path.parent.mkdir(parents=True, exist_ok=True)
    rendered_command = " ".join(command)
    for value in mask_values:
        if value:
            rendered_command = rendered_command.replace(value, "***")
    lines = [
        "=" * 80,
        f"{timestamp.isoformat()} | exit={returncode}",
        rendered_command,
        "--- stdout ---",
        stdout.rstrip(),
        "--- stderr ---",
        stderr.rstrip(),
    ]
    with log_path.open("a", encoding="utf-8") as handle:
        handle.write("\n".join(lines).rstrip())
        handle.write("\n")


def prepend_history(history_path: Path, entry: str) -> None:
    history_path.parent.mkdir(parents=True, exist_ok=True)
    try:
        existing = history_path.read_text(encoding="utf-8")
    except FileNotFoundError:
        existing = ""
    history_path.write_text(entry + ("\n" + existing if existing else ""), encoding="utf-8")


def github_request(github_cfg: dict[str, Any], token: str | None, path: str, params: dict[str, Any] | None = None) -> tuple[Any, dict[str, str]]:
    api_url = github_cfg.get("api_url", "https://api.github.com")
    base = api_url.rstrip("/") + path
    if params:
        query = urllib.parse.urlencode(params)
        url = f"{base}?{query}"
    else:
        url = base
    request = urllib.request.Request(url)
    request.add_header("Accept", "application/vnd.github+json")
    if token:
        request.add_header("Authorization", f"Bearer {token}")
    with urllib.request.urlopen(request, timeout=60) as response:
        body = response.read().decode("utf-8")
        headers = {key.lower(): value for key, value in response.headers.items()}
        if not body:
            return None, headers
        data = json.loads(body)
        return data, headers


def list_org_repos(github_cfg: dict[str, Any], token: str | None, org: str) -> list[dict[str, Any]]:
    per_page = int(github_cfg.get("per_page", 100))
    page = 1
    repos: list[dict[str, Any]] = []
    while True:
        data, _headers = github_request(
            github_cfg,
            token,
            f"/orgs/{org}/repos",
            params={"per_page": per_page, "page": page, "type": "all"},
        )
        if not data:
            break
        if not isinstance(data, list):
            raise RuntimeError(f"Unexpected GitHub response for org {org}: {data}")
        repos.extend(data)
        if len(data) < per_page:
            break
        page += 1
    return repos


def filter_repos(repos: list[dict[str, Any]], include: list[str] | None, exclude: list[str] | None) -> list[dict[str, Any]]:
    include_set = {name.strip() for name in include or [] if name}
    exclude_set = {name.strip() for name in exclude or [] if name}
    filtered: list[dict[str, Any]] = []
    for repo in repos:
        name = str(repo.get("name"))
        if exclude_set and name in exclude_set:
            continue
        if include_set and name not in include_set:
            continue
        filtered.append(repo)
    return filtered


def parse_trufflehog_output(output: str, org: str) -> list[Finding]:
    findings: list[Finding] = []
    for line in output.splitlines():
        text = line.strip()
        if not text or not text.startswith("{"):
            continue
        try:
            payload = json.loads(text)
        except json.JSONDecodeError:
            continue
        source = payload.get("SourceMetadata", {}).get("Data", {}).get("Git", {})
        repo_url = source.get("repository") or source.get("Repo")
        repo_name = payload.get("Repository") or (repo_url.split("/")[-1] if repo_url else org)
        if repo_name.endswith(".git"):
            repo_name = repo_name[:-4]
        commit = source.get("commit")
        if isinstance(commit, dict):
            commit = commit.get("sha")
        file_path = source.get("path") or payload.get("File") or source.get("file") or "unknown"
        line_no = source.get("line") or payload.get("Line")
        detector = payload.get("DetectorName") or payload.get("Rule") or "Unknown"
        location = f"{file_path}:{line_no}" if line_no else file_path
        description = payload.get("Verification") or payload.get("Message") or ""
        url = build_github_blob_url(repo_url, commit, file_path)
        findings.append(
            Finding(
                scanner="trufflehog",
                org=org,
                repo=repo_name,
                rule=str(detector),
                description=str(description),
                location=str(location),
                commit=str(commit or ""),
                url=url,
                raw=payload,
            )
        )
    return findings


def parse_gitleaks_output(output: str, org: str, repo: dict[str, Any]) -> list[Finding]:
    if not output.strip():
        return []
    try:
        payload = json.loads(output)
    except json.JSONDecodeError:
        return []
    findings: list[Finding] = []
    repo_name = str(repo.get("name"))
    clone_url = repo.get("html_url") or repo.get("clone_url")
    for item in payload:
        rule = item.get("RuleID") or item.get("Rule") or "Unknown"
        description = item.get("Description") or item.get("Match") or ""
        file_path = item.get("File") or item.get("file") or "unknown"
        line_no = item.get("Line") or item.get("StartLine")
        location = f"{file_path}:{line_no}" if line_no else file_path
        commit = item.get("Commit") or item.get("commit") or ""
        url = build_github_blob_url(clone_url, commit, file_path)
        findings.append(
            Finding(
                scanner="gitleaks",
                org=org,
                repo=repo_name,
                rule=str(rule),
                description=str(description),
                location=str(location),
                commit=str(commit),
                url=url,
                raw=item,
            )
        )
    return findings


def build_github_blob_url(repo_url: str | None, commit: str | None, file_path: str | None) -> str | None:
    if not repo_url or not commit or not file_path:
        return None
    clean = repo_url.rstrip("/")
    if clean.endswith(".git"):
        clean = clean[:-4]
    file_fragment = file_path.lstrip("/")
    return f"{clean}/blob/{commit}/{file_fragment}"


def run_trufflehog(org: str, cfg: RunContext) -> list[Finding]:
    settings = cfg.trufflehog_cfg
    if not settings.get("enabled", True):
        return []
    path = settings.get("path", "trufflehog")
    results = settings.get("results", ["verified", "unknown"])
    command = [path, "github", f"--org={org}", f"--results={','.join(results)}", "--json"]
    if settings.get("issue_comments", True):
        command.append("--issue-comments")
    if settings.get("pr_comments", True):
        command.append("--pr-comments")
    include_repo_comments = settings.get("repo_comments", False)
    if include_repo_comments:
        command.append("--repo-comments")
    include_no_update = settings.get("no_update", True)
    if include_no_update:
        command.append("--no-update")
    for extra in settings.get("extra_args", []) or []:
        command.append(str(extra))

    env = os.environ.copy()
    if cfg.token:
        env.setdefault("TRUFFLEHOG_GITHUB_TOKEN", cfg.token)
    if include_no_update:
        env.setdefault("TRUFFLEHOG_AUTO_UPDATE", "false")
        env.setdefault("TRUFFLEHOG_UPDATE", "false")
        env.setdefault("TRUFFLEHOG_DISABLE_UPDATE", "true")
        env.setdefault("TRUFFLEHOG_NO_UPDATE", "1")

    def _run(cmd: list[str]) -> subprocess.CompletedProcess[str]:
        ts = datetime.now(timezone.utc)
        proc = subprocess.run(
            cmd,
            capture_output=True,
            text=True,
            env=env,
        )
        append_log(
            cfg.log_path,
            ts,
            cmd,
            proc.stdout,
            proc.stderr,
            proc.returncode,
            mask_values=[cfg.token],
        )
        return proc

    current_command = command
    process = _run(current_command)
    if process.returncode in (0, 183):
        return parse_trufflehog_output(process.stdout, org)

    stderr_text = process.stderr or ""
    last_process = process

    if include_no_update and "--no-update" in stderr_text:
        current_command = [arg for arg in current_command if arg != "--no-update"]
        include_no_update = False
        process = _run(current_command)
        if process.returncode in (0, 183):
            return parse_trufflehog_output(process.stdout, org)
        stderr_text = process.stderr or ""
        last_process = process

    if include_repo_comments and "--repo-comments" in stderr_text:
        current_command = [arg for arg in current_command if arg != "--repo-comments"]
        include_repo_comments = False
        process = _run(current_command)
        if process.returncode in (0, 183):
            return parse_trufflehog_output(process.stdout, org)
        stderr_text = process.stderr or ""
        last_process = process

    detail = stderr_text.strip() or "no stderr from trufflehog"
    raise RuntimeError(
        f"TruffleHog failed for org {org} with exit {last_process.returncode}: {detail}"
    )
def run_gitleaks(org: str, repos: list[dict[str, Any]], cfg: RunContext) -> list[Finding]:
    settings = cfg.gitleaks_cfg
    if not settings.get("enabled", True):
        return []
    if not repos:
        return []
    path = settings.get("path", "gitleaks")
    findings: list[Finding] = []
    env = os.environ.copy()
    if cfg.token:
        env.setdefault("GITHUB_TOKEN", cfg.token)
    for repo in repos:
        repo_url = repo.get("clone_url")
        if not repo_url:
            continue
        default_branch = repo.get("default_branch") or "main"
        command: list[str] = [
            path,
            "git",
            "--repo-url",
            str(repo_url),
            "--branch",
            str(default_branch),
            "--no-banner",
            "--report-format",
            "json",
        ]
        for extra in settings.get("extra_args", []) or []:
            command.append(str(extra))
        timestamp = datetime.now(timezone.utc)
        process = subprocess.run(
            command,
            capture_output=True,
            text=True,
            env=env,
        )
        append_log(cfg.log_path, timestamp, command, process.stdout, process.stderr, process.returncode, mask_values=[cfg.token])
        if process.returncode not in (0, 1):
            raise RuntimeError(
                f"Gitleaks failed for {org}/{repo.get('name')} with exit {process.returncode}"
            )
        findings.extend(parse_gitleaks_output(process.stdout, org, repo))
    return findings


def send_discord_notification(
    webhook: str,
    generated_at: datetime,
    findings_count: int,
    processed: int,
    total_orgs: int,
    statuses: list[str],
    errors: list[str],
    report_path: Path,
    next_pointer: int,
) -> None:
    if not webhook:
        return
    try:
        report_text = report_path.read_text(encoding="utf-8")
    except FileNotFoundError:
        report_text = ""

    if errors:
        color = 0xE74C3C
        title = "Secrets scan completed with errors"
    elif findings_count:
        color = 0xF1C40F
        title = "Secrets scan found secrets"
    else:
        color = 0x2ECC71
        title = "Secrets scan completed"

    summary_lines = [
        f"Processed orgs: {processed}/{total_orgs}",
        f"Findings: {findings_count}",
        f"Errors: {len(errors)}",
        f"Next pointer: {next_pointer}",
    ]

    status_snippet = "\n".join(statuses[:10]) if statuses else "None"
    if len(status_snippet) > 1000:
        status_snippet = status_snippet[:1000] + "\n..."

    error_snippet = "\n".join(errors[:5]) if errors else "None"
    if len(error_snippet) > 1000:
        error_snippet = error_snippet[:1000] + "\n..."

    report_snippet = report_text.strip()
    if len(report_snippet) > 1000:
        report_snippet = report_snippet[:1000] + "\n..."
    if report_snippet:
        report_snippet = f"```markdown\n{report_snippet}\n```"

    embed = {
        "title": title,
        "color": color,
        "timestamp": generated_at.isoformat(),
        "fields": [
            {"name": "Summary", "value": "\n".join(summary_lines), "inline": False},
            {"name": "Recent statuses", "value": status_snippet, "inline": False},
        ],
    }

    if errors:
        embed["fields"].append({"name": "Errors", "value": error_snippet, "inline": False})
    if report_snippet:
        embed["fields"].append({"name": "Report", "value": report_snippet, "inline": False})

    payload = {"embeds": [embed]}
    data = json.dumps(payload, ensure_ascii=False).encode("utf-8")
    request = urllib.request.Request(webhook, data=data, headers={"Content-Type": "application/json"})
    try:
        urllib.request.urlopen(request, timeout=10)
    except Exception:
        # Notification failures should not break the run
        pass

def process_org(org_cfg: dict[str, Any], context: RunContext) -> tuple[list[Finding], int]:
    org_name = str(org_cfg.get("name"))
    if not org_name:
        raise RuntimeError("Org configuration missing name")
    print(f"[+] Scanning org: {org_name}")
    repos_full = list_org_repos(context.github_cfg, context.token, org_name)
    repos = filter_repos(
        repos_full,
        org_cfg.get("include_repos"),
        org_cfg.get("exclude_repos"),
    )
    print(f"    Repositories selected: {len(repos)} of {len(repos_full)} total")
    org_findings: list[Finding] = []
    trufflehog_findings = run_trufflehog(org_name, context)
    if trufflehog_findings:
        print(f"    TruffleHog findings: {len(trufflehog_findings)}")
    org_findings.extend(trufflehog_findings)
    gitleaks_findings = run_gitleaks(org_name, repos, context)
    if gitleaks_findings:
        print(f"    Gitleaks findings: {len(gitleaks_findings)}")
    org_findings.extend(gitleaks_findings)
    return org_findings, len(repos)


def build_context(config: dict[str, Any], base_dir: Path) -> RunContext:
    github_cfg = config.get("github") or {}
    scanners_cfg = config.get("scanners") or {}
    run_cfg = config.get("run") or {}
    trufflehog_cfg = scanners_cfg.get("trufflehog") or {}
    gitleaks_cfg = scanners_cfg.get("gitleaks") or {}
    token = github_cfg.get("token") or None
    log_path = resolve_path(base_dir, run_cfg.get("raw_log_path", "logs/raw.log"))
    history_path = resolve_path(base_dir, run_cfg.get("history_path", "history.txt"))
    state_path = resolve_path(base_dir, run_cfg.get("state_path", "state.txt"))
    report_path = resolve_path(base_dir, run_cfg.get("report_path", "artifacts/report.md"))
    raw_dir = resolve_path(base_dir, run_cfg.get("raw_output_dir", "artifacts/raw"))
    return RunContext(
        github_cfg=github_cfg,
        trufflehog_cfg=trufflehog_cfg,
        gitleaks_cfg=gitleaks_cfg,
        run_cfg=run_cfg,
        token=token,
        log_path=log_path,
        history_path=history_path,
        state_path=state_path,
        report_path=report_path,
        raw_dir=raw_dir,
    )


def main() -> int:
    args = parse_args()
    config_path = Path(args.config).resolve()
    config = load_config(config_path)
    orgs = config.get("orgs") or []
    if not orgs:
        raise SystemExit("No orgs defined in configuration")
    base_dir = config_path.parent
    context = build_context(config, base_dir)
    reporter = Reporter(context.report_path)
    state_tracker = StateTracker(context.state_path)

    total_orgs = len(orgs)
    pointer = 0
    if args.force and args.start_index is None:
        pointer = 0
    elif args.start_index is not None:
        pointer = args.start_index % total_orgs
    else:
        pointer = state_tracker.current() % total_orgs

    max_orgs_config = context.run_cfg.get("max_orgs_per_run")
    max_orgs = args.max_orgs or max_orgs_config or total_orgs
    max_orgs = int(max(1, min(total_orgs, int(max_orgs))))

    processed = 0
    all_findings: list[Finding] = []
    statuses_log: list[str] = []
    errors: list[str] = []
    for offset in range(max_orgs):
        org_index = (pointer + offset) % total_orgs
        org_cfg = orgs[org_index]
        now = datetime.now(timezone.utc)
        try:
            findings, repo_count = process_org(org_cfg, context)
            status = f"OK ({len(findings)} findings, {repo_count} repos)"
            all_findings.extend(findings)
        except Exception as exc:
            status = f"ERROR ({exc})"
            print(f"[!] {status}")
            errors.append(str(exc))
        history_entry = f"{now.isoformat()} | {org_cfg.get('name')} | {status}"
        prepend_history(context.history_path, history_entry)
        statuses_log.append(history_entry)
        if status.startswith("ERROR") and context.run_cfg.get("stop_on_error"):
            break
        processed += 1
    new_pointer = (pointer + processed) % total_orgs
    state_tracker.update(new_pointer)

    deduped = dedupe_findings(all_findings)
    run_finished = datetime.now(timezone.utc)
    run_id = run_finished.strftime("%Y%m%dT%H%M%SZ")
    reporter.write_raw_jsonl(deduped, run_id, context.raw_dir)
    reporter.write_markdown(deduped, run_finished)
    webhook_url = config.get("notifications", {}).get("discord_webhook", "")
    if webhook_url:
        send_discord_notification(
            webhook_url,
            run_finished,
            len(deduped),
            processed,
            total_orgs,
            statuses_log,
            errors,
            context.report_path,
            new_pointer,
        )
    print(f"Run complete. Processed {processed} org(s). Findings: {len(deduped)}. Next index: {new_pointer}.")
    return 0


if __name__ == "__main__":
    try:
        raise SystemExit(main())
    except KeyboardInterrupt:
        raise SystemExit(130)



















