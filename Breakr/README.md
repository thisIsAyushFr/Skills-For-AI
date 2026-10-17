# Breakr

**A multi-agent security auditor for codebases, built to be used as an AI skill.**

Breakr points ten specialised "breaker" agents at a project folder. Each one
hunts for a class of vulnerability that shows up again and again in real apps,
especially apps built fast with AI help: leaked keys, routes with no auth,
Supabase tables without Row Level Security, SQL built with f-strings, and so on.

The scanner is deterministic and needs only the Python standard library. Its
findings are **leads**. When Breakr runs as a skill (see [`SKILL.md`](SKILL.md)),
the AI reads each lead against the real code, using the triage guides in
[`Prompts/`](Prompts), and reports only what holds up, with fixes.

Output from a run on the deliberately vulnerable test project, trimmed:

```
$ python main.py ../my-app

BREAKR 1.0.0
...
Technologies:
- Django, Docker, Express, Firebase, Flask, JWT, Next.js, Node.js, Python, React, SQL, Supabase, TypeScript

Selected Agents:
- SecretBreaker (always runs)
- AuthBreaker (Django, Express, Flask, Next.js, Node.js, Python detected)
- SupabaseFirebaseBreaker (Firebase, Supabase detected)
...

[CRITICAL] BRK-003 Supabase service_role key committed to the repository
  Location:   src/lib/supabase.js:2
  Agent:      SupabaseFirebaseBreaker   Confidence: 0.95   CWE-798
  Evidence:   export const supabaseAdmin = createClient(process.env.SUPABASE_URL, "eyJh************");
...
========================================
Audit complete.
Risk level: CRITICAL
Findings: CRITICAL 5  HIGH 41  MEDIUM 23  LOW 7  INFO 0  (total 76)
Correlated locations: 4
Report: .../Breakr/Reports/security_report.json
Report: .../Breakr/Reports/security_report.md
```

---

## The 10 agents

| # | Agent | Finds | Runs when |
|---|---|---|---|
| 1 | **SecretBreaker** | AWS, GitHub, Stripe, OpenAI, OpenRouter, Anthropic, Slack, SendGrid, Twilio and Google keys; private keys; DB URLs with passwords; hardcoded passwords/tokens; `.env` files that git doesn't ignore. Evidence is always masked. | always |
| 2 | **AuthBreaker** | POST/PUT/PATCH/DELETE routes, Next.js server actions and API handlers with no authentication; admin routes with no role check; webhooks with no signature check; role checks done only in the browser; tokens in `localStorage` | a web stack is detected |
| 3 | **APIBreaker** | Sensitive GET endpoints with no auth, IDOR (fetch by id without an ownership check), mass assignment (`User.create(req.body)`), stack traces sent to clients, login endpoints with no rate limiting | a web stack is detected |
| 4 | **InjectionBreaker** | SQL injection (f-strings, template literals, concatenation, `$queryRawUnsafe`), NoSQL injection, command injection, `eval`/`exec`, SSTI, `pickle`/`yaml.load`, XXE | always |
| 5 | **XSSBreaker** | `dangerouslySetInnerHTML`, `innerHTML`, `v-html`, `{@html}`, Angular sanitiser bypass, URL data written into the DOM, reflected input, `\|safe`, autoescape off, EJS `<%-`, Handlebars `{{{ }}}` | a frontend or server-rendered stack is detected |
| 6 | **ConfigBreaker** | Debug mode, CORS `*` (HIGH when combined with credentials), insecure cookies, weak session secrets, TLS verification off, CSRF off, GraphQL introspection, missing `helmet`, containers running as root | always |
| 7 | **DependencyBreaker** | Known-vulnerable npm/PyPI versions (curated offline list, or live [OSV.dev](https://osv.dev) with `--osv`), `*`/`latest`/git dependencies, missing lockfiles, unpinned requirements. Reads lockfiles for the versions actually installed. | a `package.json`, `requirements*.txt`, `pyproject.toml` or `Pipfile` exists |
| 8 | **CryptoBreaker** | MD5/SHA used for passwords, low bcrypt/PBKDF2 cost, plaintext password comparison, `Math.random()` used for tokens, JWT `none` / unverified / expiry ignored / hardcoded secret, DES/RC4/ECB, static IVs, TLS < 1.2, RSA < 2048 bits | always |
| 9 | **SupabaseFirebaseBreaker** | Supabase `service_role` keys (found by decoding the JWT), `sb_secret_` keys, secrets in `NEXT_PUBLIC_`/`VITE_` variables, admin SDKs in client code, tables without RLS, `USING (true)` policies, grants to `anon`, open or test-mode Firebase rules | Supabase or Firebase is detected |
| 10 | **FileUploadBreaker** | Path traversal, uploads saved under the client's filename, no size or type limits (multer, express-fileupload, Flask, FastAPI), uploads served from your domain, SVG uploads, Zip Slip | a web stack is detected |

The **Head Agent** (`Core/head_agent.py`) does four things:

- It picks the agents that fit the detected stack.
- It runs them, and one crashing agent never stops the audit.
- It removes duplicates and halves the confidence of findings in test, fixture, example and seed code.
- It groups lines flagged by more than one agent (`correlated_groups`). Those are the best place to start.

### How Breakr keeps noise down

- **Comments are ignored.** Comments are blanked before matching, and line numbers stay correct.
- **Rules that look for code ignore string contents.** A rule like the one for `verify=False` doesn't fire on documentation strings.
- **Auth is traced across files.** A route counts as protected when the auth check is in its handler, at file level (`router.use(requireAuth)`, `APIRouter(dependencies=...)`, `before_request`), or in the file that mounts it (`app.use('/admin', requireAdmin, adminRouter)`).
- **Public routes aren't flagged.** Login, signup, health checks and webhooks are recognised as public. Webhooks get their own check: is the signature verified?
- **Placeholders aren't secrets.** Values like `your-api-key`, `${VAR}`, package versions and translation files are skipped. A `.env` file that git ignores is treated as the right place for secrets. Breakr asks `git check-ignore`, so nested `.gitignore` files count, and it falls back to reading `.gitignore` files outside a git repo.
- **Built bundles are skipped.** Minified JS/CSS (very long average line length) isn't your source and is ignored.
- **Intentional fixtures can opt out.** A file whose first 2 KB contain a comment line that is exactly `breakr: ignore-file` (`# breakr: ignore-file`, `// breakr: ignore-file`, ...) is skipped and listed under `ignored_files` in the report. `--include-ignored` scans such files anyway. Breakr's own vulnerable test fixtures use this, so a self-audit reports 0 findings.
- **A sanitiser in the file lowers the severity.** If XSS or path findings sit in a file that calls DOMPurify, `secure_filename`, `basename` or similar, Breakr lowers the severity and asks you to confirm the sanitiser covers that exact value.
- **A "safe" project is tested to give zero findings.** The test suite contains a project that follows secure practices, and the tests fail if any agent reports anything on it.

---

## Install

Requires **Python 3.11+** (the newest stdlib module used is `tomllib`; the test suite is run on 3.13 and 3.14). No packages to install.

```bash
git clone https://github.com/thisIsAyushFr/Skills-For-AI
cd Skills-For-AI/Breakr
python main.py --list-agents
```

### Use it as a Claude Code skill

Copy (or link) the `Breakr` folder into a skills directory:

```bash
# macOS / Linux: available in every project
mkdir -p ~/.claude/skills
ln -s "$(pwd)" ~/.claude/skills/breakr
```

```powershell
# Windows (PowerShell): available in every project
New-Item -ItemType Directory -Force "$HOME\.claude\skills" | Out-Null
New-Item -ItemType Junction -Path "$HOME\.claude\skills\breakr" -Target (Get-Location)
```

To use it in just one project, put it in `<project>/.claude/skills/breakr`.

Then ask Claude something like *"audit this project for security issues"* or
*"use breakr on ./my-app"*. The skill runs the scanner, reads the report,
checks every finding in the code and gives you a prioritised list of fixes.
See [`SKILL.md`](SKILL.md) for the exact workflow.

---

## Command line

```bash
python main.py <project_path> [options]
```

| Option | Description |
|---|---|
| `--agents A,B` | Run only these agents (default: picked from the detected stack) |
| `--exclude PATTERN` | Skip matching files/folders. Can be repeated: `--exclude tests --exclude "legacy/*"` |
| `--include-ignored` | Also scan files marked `breakr: ignore-file` |
| `--format json\|markdown\|both` | Report format (default `both`) |
| `--output-dir DIR` | Where reports go (default `Breakr/Reports/`) |
| `--min-severity LEVEL` | Hide findings below `CRITICAL`/`HIGH`/`MEDIUM`/`LOW`/`INFO` |
| `--min-confidence 0.5` | Hide findings below a confidence score |
| `--fail-on LEVEL` | Exit with code `2` if any finding is at or above `LEVEL` (for CI) |
| `--osv` | Look up dependencies on OSV.dev (needs internet; sends only package names and versions) |
| `--quiet` | Summary only |
| `--no-color` | Plain output (also respects `NO_COLOR`) |
| `--list-agents` | Describe every agent and exit |
| `--debug` | Show tracebacks if an agent crashes |
| `--version` | Print the version |

Exit codes:

- `0`: success
- `1`: error, such as a missing folder, a path that is a file, an unknown agent, invalid arguments, or a report directory that can't be written
- `2`: the `--fail-on` threshold was reached, and nothing else

A crashing agent doesn't change the exit code: its error is printed and recorded under `agents[].error`, and the other agents still run.

### In CI (GitHub Actions)

```yaml
- uses: actions/setup-python@v5
  with: { python-version: "3.12" }
- run: python Breakr/main.py . --fail-on HIGH --exclude Breakr --quiet
```

### Reports

Each run writes `security_report.json` (for tools and the AI) and
`security_report.md` (for people). The JSON contains:

```jsonc
{
  "tool": "Breakr", "version": "1.0.0", "generated_at": "...",
  "project": { "project_path": "...", "technologies": [ ... ], "file_count": 17, "ignored_files": [] },
  "summary": { "risk_level": "CRITICAL", "total_findings": 76, "severity_counts": { ... },
               "agent_counts": { ... }, "correlated_groups": 4 },
  "agents": [ { "name": "AuthBreaker", "reason": "Express, Next.js detected", "findings": 12,
                "seconds": 0.04, "error": null, "prompt_file": "Prompts/Auth.txt", ... } ],
  "skipped_agents": [ ... ],
  "findings": [ { "id": "BRK-003", "agent": "SupabaseFirebaseBreaker", "title": "...",
                  "severity": "CRITICAL", "confidence": 0.95, "file": "src/lib/supabase.js",
                  "line": 2, "evidence": "...masked...", "explanation": "...",
                  "recommendation": "...", "cwe": "CWE-798" } ],
  "correlated_groups": [ { "group_id": 1, "file": ".env", "line": 1, "finding_count": 2,
                           "agents": ["SecretBreaker"], "finding_ids": ["BRK-010", "BRK-020"] } ]
}
```

---

## Project layout

```
Breakr/
├── SKILL.md                 # Skill definition: how the AI runs and reviews an audit
├── main.py                  # CLI entry point
├── Core/
│   ├── Scanner.py           # Walks the project, detects languages/frameworks/services
│   └── head_agent.py        # Picks agents, runs them, dedupes, correlates
├── Agents/
│   ├── __init__.py          # AGENT_REGISTRY: the list of agents
│   ├── base_breaker.py      # BaseBreaker, Rule, file walking, comment/string stripping
│   ├── web_routes.py        # Route discovery and auth detection (shared by Auth/API)
│   ├── Secret_breaker.py    ├── Injection_breaker.py   ├── Dependency_breaker.py
│   ├── Auth_breaker.py      ├── XSS_breaker.py         ├── Crypto_breaker.py
│   ├── API_breaker.py       ├── Config_breaker.py      ├── Supabase_firebase_breaker.py
│   └── FileUpload_breaker.py
├── Models/                  # Finding, ProjectProfile
├── Prompts/                 # Triage guides the AI uses to verify each agent's findings
├── Reports/Reporter.py      # JSON and Markdown reports (generated reports also land here)
└── tests/                   # Vulnerable and safe fixture projects + unit tests
```

## Adding an agent

1. Create `Agents/MyThing_breaker.py`:

   ```python
   from Agents.base_breaker import BaseBreaker, Rule, JS_EXTENSIONS

   RULES = [
       Rule(
           title="Something dangerous",
           pattern=r"dangerousCall\(",
           severity="HIGH",
           confidence=0.7,
           explanation="Why it matters.",
           recommendation="How to fix it.",
           cwe="CWE-000",
           extensions=frozenset(JS_EXTENSIONS),
       ),
   ]

   class MyThingBreaker(BaseBreaker):
       name = "MyThingBreaker"
       description = "One line for --list-agents"
       prompt_file = "MyThing.txt"
       always_run = True          # or trigger_technologies = {"Express"}

       def scan_file(self, file_path, content):
           return self.scan_rules(file_path, content, RULES)
   ```

2. Add it to `AGENT_REGISTRY` in `Agents/__init__.py`.
3. Write `Prompts/MyThing.txt`, the triage guide the AI follows.
4. Add vulnerable and safe examples to `tests/fixtures.py`, plus a test.

## Tests

```bash
cd Breakr
python -m unittest discover -s tests -t . -v
```

The tests build two throwaway projects in a temp folder. One is deliberately
vulnerable and covers every agent. The other follows secure practices and must
produce **zero** findings. Fake secrets are put together at runtime, so none
are ever committed.

The suite also covers:

- the CLI end to end: report formats, `--agents`, `--exclude`, `--fail-on`
- error handling: missing or invalid paths, bad arguments, an unwritable
  output directory, an agent that crashes
- the ignore marker
- a clean self-audit of Breakr itself
- the skill files: `SKILL.md` frontmatter, and a triage prompt for every agent

## Limitations

Breakr reads source code. It can't see:

- runtime config or environment variables in production
- cloud, IAM and network settings
- settings in your auth provider's dashboard
- RLS policies that exist only in the Supabase dashboard
- business-logic flaws

Its other limits:

- **Data flow:** analysis is heuristic and looks at one file at a time. The
  only cross-file tracing is for router mounting.
- **Route detection:** covers Express/Fastify/Koa-style routers,
  Flask/FastAPI decorators, NestJS, and Next.js App Router, Pages API and
  Server Actions. Django URLconf views are not analysed for auth.
- **Dependency advisories:** the built-in list is a small, curated snapshot
  (about 40 high-impact advisories). Use `--osv` for current data.

Use Breakr alongside dependency audits (`npm audit`, `pip-audit`), a dynamic
scanner, and human review. It doesn't replace any of them.

Only scan code you own or are authorised to test.

## License

MIT. See [LICENSE](../LICENSE).
