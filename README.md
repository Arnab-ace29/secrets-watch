# Secrets Watcher Lite

This stripped-down setup runs **TruffleHog** and **Gitleaks** across every GitHub organization you list, captures raw command output, turns it into a concise Markdown report, and pushes alerts to Discord when new secrets appear.

## Requirements
- Python 3.11+
- `git`, `trufflehog`, `gitleaks` on `PATH`
- Python packages: `PyYAML`

```bash
python -m venv .venv
.\.venv\Scripts\activate
pip install PyYAML
```

## Configure
Edit `config.yaml` to supply your GitHub token, target orgs, and optional Discord webhook. All paths are relative to the project root.

Key settings:
- `github.token` – personal access token with `repo` + `security_events`
- `orgs` – every org you want scanned (order matters for resume logic)
- `scanners.trufflehog` / `scanners.gitleaks` – binary paths and flags
- `dorks.queries` - optional GitHub code-search keywords used as a prefilter before cloning repos.
- `run.log_level` - set to `INFO` (default) or `DEBUG` to control console verbosity.
- `run` – where to save reports, logs, and state

## Run
```bash
python main.py --config config.yaml
```
Optional flags:
- `--max-orgs N` – only process the next N orgs (defaults to the entire list)
- `--start-index I` – ignore the saved pointer and begin at org index `I`
- `--force` – ignore resume pointer and always start at the top
- `--dorks {0,1}` - override the dork prefilter (0 disables, 1 forces enable; default comes from config)

`state.txt` tracks the next org index so interrupted runs resume automatically. `history.txt` keeps a reverse-chronological log of completed org scans.

## Outputs
- `logs/raw.log` – append-only text containing every scanner invocation with stdout/stderr
- `artifacts/report.md` – latest processed findings, suitable for copy/paste
- `artifacts/raw/<timestamp>_findings.jsonl` – structured newline JSON of the run
- `history.txt` – newest entries first, showing when each org was scanned

If `notifications.discord_webhook` is set and findings are detected, the script posts the freshly generated report (or a truncated version if oversized) to the supplied webhook.

## Notes
- TruffleHog handles repos, PR comments, and issue comments by using `--issue-comments` and `--pr-comments` automatically.
- Gitleaks is executed once per repository returned by the GitHub API for broad coverage.
- Exit codes from both tools are captured but do not stop the run unless `stop_on_error` is set in the config.
- All secrets remain in local files; ensure you protect the output directory.
