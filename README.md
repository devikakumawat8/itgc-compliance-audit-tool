# GitHub ITGC Audit Tool

A lightweight Python CLI that audits a GitHub user's or org's public repositories against IT General Controls (ITGC) domains commonly reviewed in an IT audit: **Access Control**, **Change Management**, **Secrets Hygiene**, **Documentation**, and **Monitoring**.

No external dependencies — uses only the Python standard library (`urllib`) against the public GitHub REST API and `raw.githubusercontent.com`.

## What it checks

| ITGC Domain | Control | How it's checked |
|---|---|---|
| Documentation | README / LICENSE / SECURITY.md present | Repo file tree (Git Trees API) |
| Change Management | CI/CD pipeline configured | Presence of `.github/workflows/` |
| Secrets Hygiene | Sensitive filenames tracked in repo | Filename pattern match (`.env`, `*.pem`, `id_rsa`, `credentials.json`, etc.) |
| Secrets Hygiene | Hardcoded secret patterns in sampled files | Regex scan for AWS keys, GCP keys, private key blocks, GitHub/Slack tokens |
| Monitoring | Repository activity | Days since last push vs. a staleness threshold |
| Access Control | Branch protection on default branch | Branch Protection API (**requires an authenticated token** — reported as `NOT ASSESSED` otherwise) |

## Usage

```bash
# Unauthenticated (public-only checks)
python github_itgc_audit.py --user devikakumawat08

# Authenticated (adds branch-protection checks)
python github_itgc_audit.py --user devikakumawat08 --token <github_pat> --out findings.csv
```

Outputs a CSV (`Repository, Control Domain, Control, Status, Severity, Detail`) plus a console summary and a list of open (`FAIL`) findings.

## Sample run (unauthenticated, against devikakumawat08)

```
Auditing 8 non-fork, non-archived public repo(s) for devikakumawat08...

64 control checks run across 8 repos
  PASS         : 21
  FAIL         : 35
  NOT ASSESSED : 8 (re-run with --token to unlock)
```

Notable finding: `PDF_Validator` has a tracked `.env` file matching a secrets-hygiene control failure (High severity) — a real example of the kind of control gap this tool is designed to surface.

Full results: [`github_itgc_findings.csv`](./github_itgc_findings.csv).

## Why this exists

Built to practice mapping everyday engineering hygiene (branch protection, CI gates, secret handling, documentation) to formal ITGC control language used in IT audit and SOC/ISO-style reviews — the same domains (Access Control, Change Management, Monitoring) show up in ITGC walkthroughs regardless of the underlying platform.
