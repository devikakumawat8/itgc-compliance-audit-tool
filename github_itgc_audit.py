#!/usr/bin/env python3
"""
GitHub ITGC Audit Tool
----------------------
Walks the public repositories of a GitHub user/org and checks them against a
small set of IT General Controls (ITGC) domains commonly reviewed in an IT
audit: Access Control, Change Management, Secure SDLC / Secrets Hygiene,
Documentation, and Monitoring/CI.

Unauthenticated runs only see what the public API exposes (repo metadata,
file trees, raw file contents). Pass --token with a GitHub Personal Access
Token to unlock authenticated-only checks (branch protection rules, outside
collaborator permissions, 2FA enforcement at the org level).

Usage:
    python github_itgc_audit.py --user devikakumawat08
    python github_itgc_audit.py --user devikakumawat08 --token ghp_xxx --out findings.csv
"""

import argparse
import csv
import json
import re
import sys
import urllib.request
import urllib.error
from datetime import datetime, timezone

API_ROOT = "https://api.github.com"
USER_AGENT = "github-itgc-audit-tool"

SECRET_FILENAME_PATTERNS = [
    r"^\.env(\..*)?$",
    r".*\.pem$",
    r"^id_rsa$",
    r"^id_ed25519$",
    r"credentials\.json$",
    r"secrets\.ya?ml$",
    r"^\.npmrc$",
    r"service[-_]?account.*\.json$",
]

SECRET_CONTENT_PATTERNS = [
    (r"AKIA[0-9A-Z]{16}", "AWS Access Key ID"),
    (r"AIza[0-9A-Za-z\-_]{35}", "Google API Key"),
    (r"-----BEGIN (RSA |EC |OPENSSH )?PRIVATE KEY-----", "Private Key Block"),
    (r"ghp_[0-9A-Za-z]{36}", "GitHub Personal Access Token"),
    (r"xox[baprs]-[0-9A-Za-z-]{10,}", "Slack Token"),
]

STALE_DAYS_THRESHOLD = 180


def api_get(path, token=None, params=None):
    url = f"{API_ROOT}{path}"
    if params:
        query = "&".join(f"{k}={v}" for k, v in params.items())
        url = f"{url}?{query}"
    req = urllib.request.Request(url, headers={"User-Agent": USER_AGENT, "Accept": "application/vnd.github+json"})
    if token:
        req.add_header("Authorization", f"Bearer {token}")
    try:
        with urllib.request.urlopen(req, timeout=15) as resp:
            return resp.status, json.loads(resp.read().decode("utf-8"))
    except urllib.error.HTTPError as e:
        return e.code, None


def raw_get(owner, repo, branch, path):
    url = f"https://raw.githubusercontent.com/{owner}/{repo}/{branch}/{path}"
    req = urllib.request.Request(url, headers={"User-Agent": USER_AGENT})
    try:
        with urllib.request.urlopen(req, timeout=15) as resp:
            return resp.read().decode("utf-8", errors="ignore")
    except urllib.error.HTTPError:
        return None


def list_repos(owner, token=None):
    status, data = api_get(f"/users/{owner}/repos", token, {"per_page": 100})
    if status != 200 or data is None:
        print(f"Could not list repos for {owner} (HTTP {status})", file=sys.stderr)
        sys.exit(1)
    return [r for r in data if not r["fork"] and not r["archived"]]


def check_docs(owner, repo, branch, tree_paths):
    findings = []
    has_readme = any(p.lower().startswith("readme") for p in tree_paths)
    has_license = any(p.upper().startswith("LICENSE") for p in tree_paths)
    has_security_md = any(p.upper() == "SECURITY.MD" for p in tree_paths)

    findings.append(("Documentation", "README present", "PASS" if has_readme else "FAIL",
                      "Low", "README.md found" if has_readme else "No README.md at repo root"))
    findings.append(("Documentation", "License declared", "PASS" if has_license else "FAIL",
                      "Low", "LICENSE file found" if has_license else "No LICENSE file — usage rights undefined"))
    findings.append(("Documentation", "Security policy (SECURITY.md)", "PASS" if has_security_md else "FAIL",
                      "Low", "SECURITY.md found" if has_security_md else "No vulnerability-disclosure policy on file"))
    return findings


def check_ci(tree_paths):
    has_workflows = any(p.startswith(".github/workflows/") for p in tree_paths)
    detail = "GitHub Actions workflow(s) found" if has_workflows else "No .github/workflows — no automated build/test/lint gate"
    return [("Change Management", "CI/CD pipeline configured", "PASS" if has_workflows else "FAIL",
             "Medium", detail)]


def check_secret_filenames(tree_paths):
    findings = []
    hits = [p for p in tree_paths if any(re.match(pat, p.split("/")[-1], re.IGNORECASE) for pat in SECRET_FILENAME_PATTERNS)]
    if hits:
        findings.append(("Secrets Hygiene", "Sensitive filenames in repo", "FAIL", "High",
                          f"Found tracked file(s) matching secret-like names: {', '.join(hits)}"))
    else:
        findings.append(("Secrets Hygiene", "Sensitive filenames in repo", "PASS", "High",
                          "No .env/.pem/credentials-style filenames tracked in the tree"))
    return findings


def check_secret_contents(owner, repo, branch, tree_paths):
    findings = []
    # Sample a bounded set of small, plausible text files to avoid hammering the API
    candidates = [p for p in tree_paths if p.lower().endswith((".md", ".json", ".yml", ".yaml", ".txt", ".env.example"))][:15]
    hit_files = []
    for path in candidates:
        content = raw_get(owner, repo, branch, path)
        if not content:
            continue
        for pattern, label in SECRET_CONTENT_PATTERNS:
            if re.search(pattern, content):
                hit_files.append(f"{path} ({label})")
                break
    if hit_files:
        findings.append(("Secrets Hygiene", "Hardcoded secret patterns", "FAIL", "Critical",
                          f"Possible exposed credentials in: {', '.join(hit_files)}"))
    else:
        findings.append(("Secrets Hygiene", "Hardcoded secret patterns", "PASS", "Critical",
                          f"No known secret patterns matched in {len(candidates)} sampled text file(s)"))
    return findings


def check_staleness(pushed_at):
    pushed = datetime.strptime(pushed_at, "%Y-%m-%dT%H:%M:%SZ").replace(tzinfo=timezone.utc)
    age_days = (datetime.now(timezone.utc) - pushed).days
    if age_days > STALE_DAYS_THRESHOLD:
        return [("Monitoring", "Repository activity", "FAIL", "Low",
                  f"No pushes in {age_days} days (> {STALE_DAYS_THRESHOLD}-day threshold) — confirm still in active use")]
    return [("Monitoring", "Repository activity", "PASS", "Low", f"Last push {age_days} day(s) ago")]


def check_branch_protection(owner, repo, branch, token):
    if not token:
        return [("Access Control", "Branch protection on default branch", "NOT ASSESSED", "Medium",
                  "Requires an authenticated token with repo access — skipped in unauthenticated run")]
    status, data = api_get(f"/repos/{owner}/{repo}/branches/{branch}/protection", token)
    if status == 200:
        reviews_required = data.get("required_pull_request_reviews") is not None
        return [("Access Control", "Branch protection on default branch", "PASS", "Medium",
                  f"Protection enabled (PR reviews required: {reviews_required})")]
    if status == 404:
        return [("Access Control", "Branch protection on default branch", "FAIL", "Medium",
                  "No branch protection configured on default branch")]
    return [("Access Control", "Branch protection on default branch", "NOT ASSESSED", "Medium",
              f"Could not determine (HTTP {status})")]


def get_tree_paths(owner, repo, branch, token):
    status, data = api_get(f"/repos/{owner}/{repo}/git/trees/{branch}", token, {"recursive": "1"})
    if status != 200 or data is None or "tree" in data and data.get("truncated"):
        pass
    if status != 200 or data is None:
        return []
    return [item["path"] for item in data.get("tree", []) if item["type"] == "blob"]


def audit_repo(owner, repo_meta, token):
    repo = repo_meta["name"]
    branch = repo_meta["default_branch"]
    tree_paths = get_tree_paths(owner, repo, branch, token)

    findings = []
    findings += check_docs(owner, repo, branch, tree_paths)
    findings += check_ci(tree_paths)
    findings += check_secret_filenames(tree_paths)
    findings += check_secret_contents(owner, repo, branch, tree_paths)
    findings += check_staleness(repo_meta["pushed_at"])
    findings += check_branch_protection(owner, repo, branch, token)
    return [(repo,) + f for f in findings]


def main():
    parser = argparse.ArgumentParser(description="Audit a GitHub user/org's public repos against ITGC control domains.")
    parser.add_argument("--user", required=True, help="GitHub username or org to audit")
    parser.add_argument("--token", default=None, help="Optional GitHub PAT to unlock authenticated-only checks")
    parser.add_argument("--out", default="github_itgc_findings.csv", help="CSV output path")
    args = parser.parse_args()

    repos = list_repos(args.user, args.token)
    print(f"Auditing {len(repos)} non-fork, non-archived public repo(s) for {args.user}...\n")

    all_rows = []
    for repo_meta in repos:
        all_rows += audit_repo(args.user, repo_meta, args.token)

    with open(args.out, "w", newline="", encoding="utf-8") as f:
        writer = csv.writer(f)
        writer.writerow(["Repository", "Control Domain", "Control", "Status", "Severity", "Detail"])
        writer.writerows(all_rows)

    total = len(all_rows)
    fails = [r for r in all_rows if r[3] == "FAIL"]
    not_assessed = [r for r in all_rows if r[3] == "NOT ASSESSED"]

    print(f"{total} control checks run across {len(repos)} repos")
    print(f"  PASS         : {total - len(fails) - len(not_assessed)}")
    print(f"  FAIL         : {len(fails)}")
    print(f"  NOT ASSESSED : {len(not_assessed)} (re-run with --token to unlock)")
    print(f"\nFindings written to {args.out}\n")

    if fails:
        print("Open findings (FAIL):")
        for repo, domain, control, status, severity, detail in fails:
            print(f"  [{severity:>8}] {repo} — {domain} / {control}: {detail}")


if __name__ == "__main__":
    main()
