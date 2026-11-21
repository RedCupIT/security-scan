#!/usr/bin/env python3
"""Daily Gheist detector (SEC-502).

Read-only sweep of every non-archived repo in the org:
  1. gaps in run_number per workflow (deleted runs),
  2. workflow files on any branch matching secret-dump patterns,
  3. Actions runs by actors outside the allowlist.
Findings go to the job summary, Slack and a new Linear issue.
Stdlib only.
"""

import base64
import datetime as dt
import json
import os
import re
import sys
import urllib.error
import urllib.parse
import urllib.request

ORG = os.environ.get("ORG", "RedCupIT")
GH_TOKEN = os.environ["GH_TOKEN"]
LOOKBACK_HOURS = int(os.environ.get("LOOKBACK_HOURS") or 26)
HISTORY_DAYS = int(os.environ.get("HISTORY_DAYS") or 7)
DRY_RUN = os.environ.get("DRY_RUN", "false").lower() == "true"
ALLOWED_ACTORS = {
    a.strip().lower()
    for a in (
        os.environ.get("ALLOWED_ACTORS")
        or "dan-redcupit,deepak-redcupit,dependabot[bot],devin-ai-integration[bot],github-advanced-security[bot]"
    ).split(",")
    if a.strip()
}
SLACK_TOKEN = os.environ.get("SLACK_BOT_TOKEN", "")
SLACK_CHANNEL = os.environ.get("SLACK_CHANNEL") or "CD7MTR4JF"
LINEAR_API_KEY = os.environ.get("LINEAR_API_KEY", "")
LINEAR_TEAM_ID = os.environ.get("LINEAR_TEAM_ID") or "17d743c5-c0ec-48ca-ba09-e2a9d0b97ea0"
LINEAR_LABEL_ID = os.environ.get("LINEAR_LABEL_ID") or "d7042d25-5895-4fec-a693-7d544de4f9ba"

SECRET_DUMP_PATTERNS = [
    ("toJSON(secrets)", r"toJSON\(\s*secrets\s*\)"),
    ("${{ secrets }}", r"\$\{\{\s*secrets\s*\}\}"),
    ("printenv", r"\bprintenv\b"),
    ("env piped", r"(^|[\s;&(])env\s*\|\s*(base64|grep|sort|curl|nc|xxd|gzip|openssl|tee)\b"),
    ("base64 -w0", r"\bbase64\s+-w\s*0\b"),
    ("xxd", r"\bxxd\b"),
    ("/proc/*/environ", r"/proc/(self|\d+|\*|\$\w+)/environ"),
    ("curl posting secrets", r"\bcurl\b[^\n]*(\s-d\s|--data|\s-F\s|--form)[^\n]*\$\{\{\s*secrets\."),
]
SECRET_DUMP_RE = [(name, re.compile(rx, re.IGNORECASE | re.MULTILINE)) for name, rx in SECRET_DUMP_PATTERNS]

NOW = dt.datetime.now(dt.timezone.utc)
RECENT = NOW - dt.timedelta(hours=LOOKBACK_HOURS)


def gh(path, params=None):
    url = path if path.startswith("https://") else f"https://api.github.com/{path.lstrip('/')}"
    if params:
        url += ("&" if "?" in url else "?") + urllib.parse.urlencode(params)
    req = urllib.request.Request(
        url,
        headers={
            "Authorization": f"Bearer {GH_TOKEN}",
            "Accept": "application/vnd.github+json",
            "X-GitHub-Api-Version": "2022-11-28",
        },
    )
    try:
        with urllib.request.urlopen(req, timeout=60) as resp:
            return json.load(resp), resp.headers.get("Link", "")
    except urllib.error.HTTPError as e:
        if e.code in (404, 409):
            return None, ""
        raise


def gh_paged(path, params=None, key=None):
    params = dict(params or {}, per_page=100)
    url, first = path, True
    while url:
        data, link = gh(url, params if first else None)
        first = False
        if data is None:
            return
        yield from (data[key] if key else data)
        m = re.search(r'<([^>]+)>;\s*rel="next"', link)
        url = m.group(1) if m else None


def ts(s):
    return dt.datetime.fromisoformat(s.replace("Z", "+00:00"))


def check_runs(repo, findings):
    since = (NOW - dt.timedelta(days=HISTORY_DAYS)).strftime("%Y-%m-%dT%H:%M:%SZ")
    by_wf = {}
    for run in gh_paged(f"repos/{ORG}/{repo}/actions/runs", {"created": f">={since}"}, key="workflow_runs"):
        by_wf.setdefault(run["workflow_id"], []).append(run)
        if ts(run["created_at"]) < RECENT:
            continue
        for who in {(run.get("actor") or {}).get("login"), (run.get("triggering_actor") or {}).get("login")}:
            if who and who.lower() not in ALLOWED_ACTORS:
                findings.append({
                    "check": "unknown-actor", "repo": repo,
                    "detail": f"{run['name']} run #{run['run_number']} by `{who}` ({run['event']})",
                    "url": run["html_url"],
                })
    for runs in by_wf.values():
        runs.sort(key=lambda r: r["run_number"])
        for prev, cur in zip(runs, runs[1:]):
            if cur["run_number"] - prev["run_number"] > 1 and ts(cur["created_at"]) >= RECENT:
                missing = list(range(prev["run_number"] + 1, cur["run_number"]))
                findings.append({
                    "check": "run-number-gap", "repo": repo,
                    "detail": f"{cur['name']} ({cur['path']}): missing run #{', #'.join(map(str, missing))} "
                              f"between {prev['created_at']} and {cur['created_at']}",
                    "url": cur["html_url"],
                })


def check_workflow_files(repo, findings, blob_cache):
    for branch in gh_paged(f"repos/{ORG}/{repo}/branches"):
        listing, _ = gh(f"repos/{ORG}/{repo}/contents/.github/workflows", {"ref": branch["commit"]["sha"]})
        if not isinstance(listing, list):
            continue
        for f in listing:
            if f["type"] != "file" or not f["name"].endswith((".yml", ".yaml")):
                continue
            sha = f["sha"]
            if sha not in blob_cache:
                blob, _ = gh(f"repos/{ORG}/{repo}/git/blobs/{sha}")
                text = base64.b64decode(blob["content"]).decode("utf-8", "replace") if blob else ""
                blob_cache[sha] = [name for name, rx in SECRET_DUMP_RE if rx.search(text)]
            if blob_cache[sha]:
                findings.append({
                    "check": "secret-dump-pattern", "repo": repo,
                    "detail": f"`{f['path']}` on branch `{branch['name']}` matches: {', '.join(blob_cache[sha])}",
                    "url": f"https://github.com/{ORG}/{repo}/blob/{branch['commit']['sha']}/{f['path']}",
                })


def render(findings, repos_scanned, errors):
    lines = [
        f"## Gheist detector, {NOW:%Y-%m-%d %H:%M} UTC",
        f"Scanned {repos_scanned} repos. Window: runs/actors last {LOOKBACK_HOURS}h, run history {HISTORY_DAYS}d, all branches for workflow files.",
        "",
    ]
    if not findings:
        lines.append("No findings.")
    for check in ("secret-dump-pattern", "unknown-actor", "run-number-gap"):
        rows = [f for f in findings if f["check"] == check]
        if rows:
            lines.append(f"### {check} ({len(rows)})")
            lines += [f"- **{f['repo']}**: {f['detail']} ([link]({f['url']}))" for f in rows]
            lines.append("")
    if errors:
        lines.append(f"### Scan errors ({len(errors)})")
        lines += [f"- {e}" for e in errors]
    lines += ["", "A run-number gap is a lead, not proof: confirm in the org audit log (`workflows.delete_workflow_run`)."]
    return "\n".join(lines)


def post_slack(text):
    body = json.dumps({"channel": SLACK_CHANNEL, "text": text, "unfurl_links": False}).encode()
    req = urllib.request.Request(
        "https://slack.com/api/chat.postMessage", data=body,
        headers={"Authorization": f"Bearer {SLACK_TOKEN}", "Content-Type": "application/json; charset=utf-8"},
    )
    with urllib.request.urlopen(req, timeout=30) as resp:
        out = json.load(resp)
    if not out.get("ok"):
        raise RuntimeError(f"Slack post failed: {out.get('error')}")


def create_linear_issue(title, description):
    query = "mutation($input: IssueCreateInput!) { issueCreate(input: $input) { success issue { identifier url } } }"
    variables = {"input": {"teamId": LINEAR_TEAM_ID, "title": title, "description": description,
                           "labelIds": [LINEAR_LABEL_ID], "priority": 2}}
    req = urllib.request.Request(
        "https://api.linear.app/graphql", data=json.dumps({"query": query, "variables": variables}).encode(),
        headers={"Authorization": LINEAR_API_KEY, "Content-Type": "application/json"},
    )
    with urllib.request.urlopen(req, timeout=30) as resp:
        out = json.load(resp)
    if out.get("errors"):
        raise RuntimeError(f"Linear issueCreate failed: {out['errors']}")
    return out["data"]["issueCreate"]["issue"]


def main():
    findings, errors, blob_cache, scanned = [], [], {}, 0
    for repo in gh_paged(f"orgs/{ORG}/repos", {"type": "all"}):
        if repo["archived"]:
            continue
        scanned += 1
        try:
            check_runs(repo["name"], findings)
            check_workflow_files(repo["name"], findings, blob_cache)
        except Exception as e:  # keep sweeping other repos
            errors.append(f"{repo['name']}: {e}")

    report = render(findings, scanned, errors)
    print(report)
    if os.environ.get("GITHUB_STEP_SUMMARY"):
        with open(os.environ["GITHUB_STEP_SUMMARY"], "a") as fh:
            fh.write(report + "\n")
    with open("gheist-findings.json", "w") as fh:
        json.dump({"generated_at": NOW.isoformat(), "findings": findings, "errors": errors}, fh, indent=2)

    if not findings:
        return 0
    if DRY_RUN:
        print("::notice::Dry run, skipping Slack and Linear.")
        return 0
    issue = None
    if LINEAR_API_KEY:
        issue = create_linear_issue(f"Gheist detector: {len(findings)} finding(s) {NOW:%Y-%m-%d}", report)
        print(f"Linear issue: {issue['url']}")
    else:
        print("::warning::LINEAR_API_KEY not set, no Linear issue created.")
    if SLACK_TOKEN:
        run_url = f"{os.environ.get('GITHUB_SERVER_URL', 'https://github.com')}/{os.environ.get('GITHUB_REPOSITORY', '')}/actions/runs/{os.environ.get('GITHUB_RUN_ID', '')}"
        counts = ", ".join(f"{c}: {sum(f['check'] == c for f in findings)}"
                           for c in ("secret-dump-pattern", "unknown-actor", "run-number-gap"))
        text = f":rotating_light: Gheist detector found {len(findings)} finding(s) ({counts}).\nRun: {run_url}"
        if issue:
            text += f"\nLinear: {issue['url']}"
        post_slack(text)
    else:
        print("::warning::SLACK_BOT_TOKEN not set, no Slack post.")
    return 0


if __name__ == "__main__":
    sys.exit(main())
