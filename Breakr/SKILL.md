---
name: breakr
description: Multi-agent security audit for a codebase. Runs 10 static "breaker" agents (secrets, auth, API exposure, injection, XSS, config, vulnerable dependencies, crypto, Supabase/Firebase, file uploads) and then verifies each lead by reading the code. Use when the user asks to audit, scan, pentest, "break", or security-review their project, check it before launch, find leaked keys, or asks "is my app secure?". Especially suited to web apps built with React/Next.js, Express, Flask/FastAPI/Django, Supabase or Firebase.
---

# Breakr: security audit skill

Breakr has two halves:

1. **Scanner (deterministic).** `main.py` runs up to 10 pattern-based agents and
   writes a JSON + Markdown report. It is fast and repeatable, but it is regex: it
   produces *leads*, not verdicts.
2. **Reviewer (you).** You verify every lead against the real code using the
   triage guides in `Prompts/`, throw out false positives, and give the user a
   short, prioritised, fixable list.

Never skip step 2. Pasting the raw scanner output is not an audit.

## When to use

Use Breakr when the user asks to:

- audit a codebase for security issues
- review an AI-generated or vibe-coded website for vulnerabilities
- scan a project for exposed secrets
- check API endpoints for security problems
- check for missing authorization
- perform a security-focused code review

Do not use Breakr for general code-quality reviews unless the user specifically
wants security analysis.

## Requirements

Python 3.11+ and nothing else (standard library only). All paths below are
relative to this skill's base directory (the folder containing this file).

## Workflow

### 1. Run the scanner

```bash
python "<skill-dir>/main.py" "<project-path>" --quiet
```

Useful options:

| Option | Use |
|---|---|
| `--quiet` | Print only the summary (read details from the report) |
| `--osv` | Check dependencies against live OSV.dev data (needs internet) |
| `--exclude PATTERN` | Skip paths, repeatable, e.g. `--exclude tests --exclude "legacy/*"` |
| `--agents A,B` | Run only some agents, e.g. `--agents SecretBreaker,SupabaseFirebaseBreaker` |
| `--min-severity HIGH` | Hide lower severities |
| `--output-dir DIR` | Where to write reports (default `<skill-dir>/Reports`) |
| `--list-agents` | Show every agent and when it runs |

Exit code 0 = ran fine, 1 = error, 2 = `--fail-on` threshold hit.

If the user only wants a quick check of one area (e.g. "did I leak any keys?"),
run only the matching agent.

### 2. Read the report

Open `Reports/security_report.json` (or the `--output-dir` you chose). Key fields:

- `summary.risk_level` and `summary.severity_counts`
- `agents[]`: what ran, why, how many findings, `error` if an agent crashed, and
  `prompt_file`, the triage guide for that agent's findings
- `findings[]`: `id` (BRK-001...), `agent`, `title`, `severity`, `confidence`,
  `file`, `line`, `evidence` (secrets are masked), `explanation`,
  `recommendation`, `cwe`
- `correlated_groups[]`: lines flagged by more than one check. Start here.

### 3. Verify the findings

Read `Prompts/Head.txt` once. It defines the review process, the verdicts
(CONFIRMED / LIKELY / FALSE POSITIVE / ACCEPTED RISK), the severity scale and
the output format. Then, for each finding, from CRITICAL down:

1. Open `file` at `line` and read the surrounding code: the whole handler, its
   imports, and where it is mounted or called from.
2. Apply the agent's triage guide (`Prompts/<Agent>.txt`).
3. Record a verdict and, for real issues, the concrete fix.

With many findings, verify every CRITICAL and HIGH one individually. Then
sample MEDIUM/LOW by title (identical titles usually share a verdict) and say
that you sampled.

Confidence below 0.5, or paths in tests, fixtures or examples, lean towards
false positive or accepted risk, but still check them.

### 4. Report to the user

Follow the output format in `Prompts/Head.txt`: verdict line, "fix these first",
a table of reviewed findings, false positives, and limits of static analysis.
Write for the person who built the app: plain language, what an attacker could
actually do, and the exact code change.

### 5. Fix (only when asked)

Offer to apply fixes. Do not edit the user's code unless they say yes. After
fixing, re-run the scanner on the project to confirm the findings are gone.

## Rules

- Never print a full secret, even if you open the file and can see it. Keep the
  masked form and tell the user to **rotate** any leaked credential; deleting
  it from code is not enough.
- The scan is read-only. It never executes the project's code or contacts the
  project's services. `--osv` sends package names and versions to OSV.dev
  only.
- Do not claim the app is "secure" because there are no findings. Say what
  was checked and what static analysis cannot see: runtime config, cloud and
  IAM settings, the auth provider dashboard, RLS state that exists only in the
  Supabase dashboard, and business-logic flaws.

## The agents

| Agent | Looks for | Triage guide |
|---|---|---|
| SecretBreaker | Leaked API keys, tokens, passwords, private keys, DB URLs, un-ignored `.env` | `Prompts/Secret.txt` |
| AuthBreaker | Data-changing routes without login, admin routes without role checks, unverified webhooks, client-only auth | `Prompts/Auth.txt` |
| APIBreaker | Sensitive GET endpoints without login, IDOR, mass assignment, error leakage, no rate limiting on login | `Prompts/Api.txt` |
| InjectionBreaker | SQL/NoSQL/command/code injection, SSTI, unsafe deserialization, XXE | `Prompts/Injection.txt` |
| XSSBreaker | innerHTML, dangerouslySetInnerHTML, v-html, `\|safe`, unescaped templates, reflected input | `Prompts/XSS.txt` |
| ConfigBreaker | Debug mode, permissive CORS, insecure cookies, TLS verification off, CSRF off, missing helmet, root containers | `Prompts/Config.txt` |
| DependencyBreaker | Known-vulnerable npm/PyPI packages, unpinned deps, missing lockfiles | `Prompts/Dependency.txt` |
| CryptoBreaker | Weak password hashing, Math.random tokens, JWT none/unverified/hardcoded secrets, ECB, weak ciphers | `Prompts/Crypto.txt` |
| SupabaseFirebaseBreaker | service_role keys in client code, tables without RLS, `USING (true)` policies, open Firebase rules | `Prompts/SupabaseFirebase.txt` |
| FileUploadBreaker | Path traversal, uploads without size/type limits, client-chosen filenames, Zip Slip | `Prompts/FileUpload.txt` |
