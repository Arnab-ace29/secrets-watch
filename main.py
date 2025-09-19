"""Entry point for the two-stage secrets watcher."""
from __future__ import annotations

import argparse
import json
import logging
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
LOG = logging.getLogger("secrets_watch")

FALSE_POSITIVE_GO_SUM = "go.sum"
FALSE_POSITIVE_PLACEHOLDERS = {
    "jdbc:postgresql://127.0.0.1:",
    "http://user:password@proxy.example.org:1234",
}

def _is_go_sum_placeholder(finding: Finding) -> bool:
    if not finding.file_path:
        return False
    if not finding.file_path.lower().endswith(FALSE_POSITIVE_GO_SUM):
        return False
    raw = finding.raw_secret or ""
    return raw.startswith("h1:")

def _is_placeholder_secret(finding: Finding) -> bool:
    raw = finding.raw_secret or ""
    return raw in FALSE_POSITIVE_PLACEHOLDERS

def filter_false_positives(candidates: list[Finding]) -> list[Finding]:
    filtered: list[Finding] = []
    for finding in candidates:
        if _is_go_sum_placeholder(finding):
            LOG.debug("Filtered go.sum checksum in %s (%s)", finding.repository.slug, finding.file_path)
            continue
        if _is_placeholder_secret(finding):
            LOG.debug("Filtered placeholder secret in %s (%s)", finding.repository.slug, finding.file_path)
            continue
        filtered.append(finding)
    return filtered




@dataclass
class RunContext:
    github_cfg: dict[str, Any]
    trufflehog_cfg: dict[str, Any]
    gitleaks_cfg: dict[str, Any]
    dorks_cfg: dict[str, Any]
    run_cfg: dict[str, Any]
    notifications_cfg: dict[str, Any]
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
    parser.add_argument("--dorks", type=int, choices=[0, 1], default=None, help="0=disable dork prefilter, 1=force enable (default: config)")
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




def configure_logging(run_cfg: dict[str, Any]) -> None:
    level_name = str(run_cfg.get("log_level", "INFO")).upper()
    level = getattr(logging, level_name, logging.INFO)
    root_logger = logging.getLogger()
    if root_logger.handlers:
        root_logger.setLevel(level)
        return
    logging.basicConfig(
        level=level,
        format="%(asctime)s %(levelname)s %(message)s",
    )


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


def filter_repos(
    repos: list[dict[str, Any]],
    include: list[str] | None,
    exclude: list[str] | None,
    limit_names: set[str] | None = None,
) -> list[dict[str, Any]]:
    include_set = {str(name).strip() for name in include or [] if name}
    exclude_set = {str(name).strip() for name in exclude or [] if name}
    limit_set = {str(name).strip() for name in limit_names or [] if name}
    filtered: list[dict[str, Any]] = []
    for repo in repos:
        name = str(repo.get("name"))
        if exclude_set and name in exclude_set:
            continue
        if include_set and name not in include_set:
            continue
        if limit_set and name not in limit_set:
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
        LOG.debug("Trufflehog disabled for %s", org)
        return []

    LOG.info("Trufflehog scan starting for org %s", org)
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
        LOG.debug("Executing: %s", " ".join(cmd))
        ts = datetime.now(timezone.utc)
        try:
            proc = subprocess.run(
                cmd,
                capture_output=True,
                text=True,
                env=env,
            )
        except FileNotFoundError as exc:
            raise FileNotFoundError("Trufflehog executable '%s' not found. Update scanners.trufflehog.path or install trufflehog." % cmd[0]) from exc
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
        findings = parse_trufflehog_output(process.stdout, org)
        LOG.info("Trufflehog completed for %s with %d finding(s)", org, len(findings))
        return findings

    stderr_text = process.stderr or ""
    last_process = process

    if include_no_update and "--no-update" in stderr_text:
        LOG.warning("Trufflehog binary for %s does not support --no-update; retrying with updates enabled", org)
        current_command = [arg for arg in current_command if arg != "--no-update"]
        include_no_update = False
        process = _run(current_command)
        if process.returncode in (0, 183):
            findings = parse_trufflehog_output(process.stdout, org)
            LOG.info("Trufflehog completed for %s with %d finding(s)", org, len(findings))
            return findings
        stderr_text = process.stderr or ""
        last_process = process

    if include_repo_comments and "--repo-comments" in stderr_text:
        LOG.warning("Trufflehog binary for %s does not support --repo-comments; retrying without comment coverage", org)
        current_command = [arg for arg in current_command if arg != "--repo-comments"]
        include_repo_comments = False
        process = _run(current_command)
        if process.returncode in (0, 183):
            findings = parse_trufflehog_output(process.stdout, org)
            LOG.info("Trufflehog completed for %s with %d finding(s)", org, len(findings))
            return findings
        stderr_text = process.stderr or ""
        last_process = process

    detail = stderr_text.strip() or "no stderr from trufflehog"
    LOG.error("Trufflehog failed for %s (exit %s): %s", org, last_process.returncode, detail)
    raise RuntimeError(
        f"TruffleHog failed for org {org} with exit {last_process.returncode}: {detail}"
    )

def run_gitleaks(org: str, repos: list[dict[str, Any]], cfg: RunContext) -> list[Finding]:
    settings = cfg.gitleaks_cfg
    if not settings.get("enabled", True):
        LOG.debug("Gitleaks disabled for %s", org)
        return []
    if not repos:
        LOG.info("No repositories selected for Gitleaks in %s", org)
        return []

    LOG.info("Gitleaks scan starting for org %s (%d repo(s))", org, len(repos))
    path = settings.get("path", "gitleaks")
    findings: list[Finding] = []
    env = os.environ.copy()
    if cfg.token:
        env.setdefault("GITHUB_TOKEN", cfg.token)
    for idx, repo in enumerate(repos, start=1):
        repo_url = repo.get("clone_url")
        if not repo_url:
            LOG.debug("Skipping repo without clone URL: %s/%s", org, repo.get('name'))
            continue
        default_branch = repo.get("default_branch") or "main"
        repo_name = str(repo.get("name"))
        LOG.info("[%s] Gitleaks scanning %s/%s (branch %s)", idx, org, repo_name, default_branch)
        command: list[str] = [
            path,
            "detect",
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
        try:
            process = subprocess.run(
                command,
                capture_output=True,
                text=True,
                env=env,
            )
        except FileNotFoundError as exc:
            raise FileNotFoundError("Gitleaks executable '%s' not found. Update scanners.gitleaks.path or install gitleaks." % command[0]) from exc
        append_log(cfg.log_path, timestamp, command, process.stdout, process.stderr, process.returncode, mask_values=[cfg.token])
        if process.returncode not in (0, 1):
            raise RuntimeError(
                f"Gitleaks failed for {org}/{repo_name} with exit {process.returncode}"
            )
        repo_findings = parse_gitleaks_output(process.stdout, org, repo)
        if repo_findings:
            LOG.info("[%s] Gitleaks found %d potential secret(s) in %s/%s", idx, len(repo_findings), org, repo_name)
        else:
            LOG.debug("[%s] No findings in %s/%s", idx, org, repo_name)
        findings.extend(repo_findings)
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

def prefilter_by_dorks(
    github_cfg: dict[str, Any],
    token: str | None,
    org: str,
    queries: list[str],
    max_results: int,
) -> set[str]:
    flagged: set[str] = set()
    per_page = max(1, min(int(max_results), 100))
    forbidden = False
    for query in queries:
        if forbidden:
            LOG.debug("Skipping remaining dork queries for %s due to earlier failure", org)
            break
        full_query = f"{query} org:{org}"
        try:
            data, _headers = github_request(
                github_cfg,
                token,
                "/search/code",
                params={"q": full_query, "per_page": per_page},
            )
        except Exception as exc:
            LOG.warning("Dork query failed for %s (%s): %s", org, query, exc)
            if "403" in str(exc):
                forbidden = True
                LOG.warning("Code search forbidden for %s; skipping remaining dork queries", org)
            continue
        items = []
        if isinstance(data, dict):
            items = data.get("items") or []
        for item in items:
            repo_info = item.get("repository") or {}
            name = repo_info.get("name")
            if name:
                flagged.add(str(name))
        LOG.debug("Dork query '%s' yielded %d result(s) for %s", query, len(items), org)
    return flagged


def send_discord_findings(
    webhook: str,
    org: str,
    scanner: str,
    findings: list[Finding],
) -> None:
    if not webhook or not findings:
        return
    snippet = findings[:5]
    generated_at = datetime.now(timezone.utc)
    lines = []
    for finding in snippet:
        repo = finding.repository.slug
        location = finding.location
        commit = finding.commit[:8] if finding.commit else ""
        lines.append(f"- {finding.secret_type} | {repo} | {location} | {commit}")
    value = "\n".join(lines)
    if len(findings) > len(snippet):
        value += f"\n... and {len(findings) - len(snippet)} more"
    embed = {
        "title": f"Secrets Watcher: {scanner} findings in {org}",
        "color": 0xF1C40F,
        "timestamp": generated_at.isoformat(),
        "fields": [
            {"name": "Findings", "value": value or "(summary unavailable)", "inline": False}
        ],
    }
    payload = {"embeds": [embed]}
    data = json.dumps(payload, ensure_ascii=False).encode("utf-8")
    request = urllib.request.Request(
        webhook, data=data, headers={"Content-Type": "application/json"}
    )
    try:
        urllib.request.urlopen(request, timeout=10)
    except Exception:
        pass


def process_org(
    org_cfg: dict[str, Any],
    context: RunContext,
    webhook_url: str | None,
    notify_immediate: bool,
) -> tuple[list[Finding], int]:
    org_name = str(org_cfg.get("name"))
    if not org_name:
        raise RuntimeError("Org configuration missing name")
    LOG.info("Scanning org %s", org_name)

    repos_full = list_org_repos(context.github_cfg, context.token, org_name)
    LOG.info("Fetched %d repository records for %s", len(repos_full), org_name)

    dorks_cfg = context.dorks_cfg or {}
    enabled_raw = dorks_cfg.get("enabled", True)
    if isinstance(enabled_raw, bool):
        dorks_enabled = enabled_raw
    else:
        dorks_enabled = str(enabled_raw).lower() not in {"0", "false", "no", "off"}
    queries = [str(q).strip() for q in dorks_cfg.get("queries", []) if str(q).strip()]
    max_results = int(dorks_cfg.get("max_results_per_query", 10))
    dork_matches: set[str] = set()
    if dorks_enabled and queries:
        dork_matches = prefilter_by_dorks(context.github_cfg, context.token, org_name, queries, max_results)
        LOG.info("Dork prefilter matched %d repo(s) for %s", len(dork_matches), org_name)
    elif not dorks_enabled:
        LOG.debug("Dork prefilter disabled for %s", org_name)

    include_repos = org_cfg.get("include_repos") or []
    exclude_repos = org_cfg.get("exclude_repos")
    limit_names = dork_matches if dork_matches and not include_repos else None

    repos = filter_repos(repos_full, include_repos, exclude_repos, limit_names=limit_names)
    LOG.info("Repositories selected: %d of %d total", len(repos), len(repos_full))
    if not repos:
        LOG.warning("No repositories selected for %s after filters", org_name)

    findings: list[Finding] = []

    trufflehog_findings = run_trufflehog(org_name, context)
    if trufflehog_findings:
        LOG.info("Trufflehog produced %d finding(s) for %s", len(trufflehog_findings), org_name)
    else:
        LOG.debug("Trufflehog produced no findings for %s", org_name)
    filtered_trufflehog = filter_false_positives(trufflehog_findings)
    findings.extend(filtered_trufflehog)
    if notify_immediate and webhook_url and filtered_trufflehog:
        send_discord_findings(webhook_url, org_name, "Trufflehog", filtered_trufflehog)

    gitleaks_findings = run_gitleaks(org_name, repos, context)
    if gitleaks_findings:
        LOG.info("Gitleaks produced %d finding(s) for %s", len(gitleaks_findings), org_name)
    else:
        LOG.debug("Gitleaks produced no findings for %s", org_name)
    filtered_gitleaks = filter_false_positives(gitleaks_findings)
    findings.extend(filtered_gitleaks)
    if notify_immediate and webhook_url and filtered_gitleaks:
        send_discord_findings(webhook_url, org_name, "Gitleaks", filtered_gitleaks)

    return findings, len(repos)





def build_context(config: dict[str, Any], base_dir: Path) -> RunContext:
    github_cfg = config.get("github") or {}
    scanners_cfg = config.get("scanners") or {}
    run_cfg = config.get("run") or {}
    trufflehog_cfg = scanners_cfg.get("trufflehog") or {}
    gitleaks_cfg = scanners_cfg.get("gitleaks") or {}
    dorks_cfg = config.get("dorks") or {}
    notifications_cfg = config.get("notifications") or {}
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
        dorks_cfg=dorks_cfg,
        run_cfg=run_cfg,
        notifications_cfg=notifications_cfg,
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
    configure_logging(config.get("run", {}))
    if args.dorks is not None:
        dorks_section = config.setdefault("dorks", {})
        dorks_section["enabled"] = bool(args.dorks)
    context = build_context(config, base_dir)
    reporter = Reporter(context.report_path)
    state_tracker = StateTracker(context.state_path)
    notifications_cfg = context.notifications_cfg or {}
    webhook_url = notifications_cfg.get("discord_webhook", "")
    notify_immediate = bool(notifications_cfg.get("immediate", False))

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
            findings, repo_count = process_org(org_cfg, context, webhook_url, notify_immediate)
            status = f"OK ({len(findings)} findings, {repo_count} repos)"
            all_findings.extend(findings)
        except Exception as exc:
            status = f"ERROR ({exc})"
            LOG.error("%s", status)
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
    LOG.info("Run complete. Processed %s org(s). Findings: %s. Next index: %s.", processed, len(deduped), new_pointer)
    return 0


if __name__ == "__main__":
    try:
        raise SystemExit(main())
    except KeyboardInterrupt:
        raise SystemExit(130)



















