# Skills-For-AI

A collection of reusable skills built to extend the capabilities of AI models.

This repository is a growing library of specialized AI skills, each designed to give an AI model a structured workflow, tools, and capabilities for a specific task.

## Skills

| Skill | Area | What it does |
|---|---|---|
| [**Breakr** 🔐](#breakr-) | Security | Multi-agent security audit for finished or AI-generated codebases |

---

## Breakr 🔐

**Security Auditing Skill**

Breakr audits a codebase for security problems in two steps:

1. **Scanner (deterministic).** Ten specialised "breaker" agents scan the
   project and write a JSON + Markdown report. This step is fast and
   repeatable and needs nothing but Python.
2. **Reviewer (AI).** The AI checks every finding against the real code, using
   a triage guide for each agent. It throws out false positives and reports
   only verified issues, each with a concrete fix.

Breakr is built for the mistakes that keep showing up in real apps, especially
apps built quickly with AI help: leaked API keys, routes with no login check,
Supabase tables without Row Level Security, SQL built from strings, and so on.

**Status:** v1.0.0 · **Requires:** Python 3.11+ (tested on 3.13 and 3.14) · **Dependencies:** none (standard library only) · **License:** MIT

### The 10 agents

| # | Agent | What it finds |
|---|---|---|
| 1 | **SecretBreaker** | Leaked API keys (AWS, GitHub, Stripe, OpenAI, OpenRouter, Anthropic, Slack, SendGrid, Twilio, Google), private keys, database URLs with passwords, hardcoded passwords/tokens, `.env` files not ignored by git. Evidence is always masked. |
| 2 | **AuthBreaker** | Routes that change data (POST/PUT/PATCH/DELETE, Next.js server actions and API routes) with no login check, admin routes with no role check, webhooks with no signature check, role checks done only in the browser, auth tokens in `localStorage` |
| 3 | **APIBreaker** | Sensitive data endpoints with no login check, IDOR (reading other users' records by ID), mass assignment (`User.create(req.body)`), stack traces sent to clients, login endpoints with no rate limiting |
| 4 | **InjectionBreaker** | SQL injection, NoSQL injection, command injection, `eval`/`exec`, server-side template injection, unsafe `pickle`/`yaml.load`, XXE |
| 5 | **XSSBreaker** | `innerHTML`, `dangerouslySetInnerHTML`, `v-html`, `{@html}`, URL data written into the page, request input echoed into HTML, `\|safe`, autoescape turned off, unescaped EJS/Handlebars output |
| 6 | **ConfigBreaker** | Debug mode, CORS open to any site (HIGH when combined with credentials), insecure cookies, weak session secrets, TLS checking turned off, CSRF turned off, missing security headers (`helmet`), containers running as root |
| 7 | **DependencyBreaker** | Known-vulnerable npm/PyPI package versions, `*`/`latest`/git dependencies, missing lockfiles, unpinned requirements. Reads lockfiles for the versions actually installed; `--osv` checks the live [OSV.dev](https://osv.dev) database. |
| 8 | **CryptoBreaker** | Passwords hashed with MD5/SHA, low bcrypt/PBKDF2 cost, plaintext password comparison, `Math.random()` used for tokens, JWT `none` / never verified / hardcoded secret, DES/RC4/ECB, fixed IVs, old TLS versions, short RSA keys |
| 9 | **SupabaseFirebaseBreaker** | Supabase `service_role` keys (found by decoding the JWT), secrets in `NEXT_PUBLIC_`/`VITE_` variables, admin SDKs in browser code, tables without RLS, `USING (true)` policies, open or test-mode Firebase rules |
| 10 | **FileUploadBreaker** | Path traversal, uploads saved under the client's filename, uploads with no size or type limit, uploads served from your domain, SVG uploads, unsafe archive extraction (Zip Slip) |

The **Head Agent** has four jobs:

- It detects the project's stack (React, Next.js, Express, Flask, FastAPI, Django, Supabase, Firebase and more) and runs only the agents that fit.
- It keeps the audit going if one agent crashes.
- It removes duplicate findings and lowers the confidence of findings in test, fixture and seed code.
- It groups lines flagged by more than one agent. Those are the best place to start.

### Quick start

```bash
git clone https://github.com/thisIsAyushFr/Skills-For-AI
cd Skills-For-AI/Breakr
python main.py path/to/your-project
```

Output from the deliberately vulnerable test project, trimmed:

```
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

### Use it as a Claude Code skill

Link the `Breakr` folder into your skills directory:

```bash
# macOS / Linux
mkdir -p ~/.claude/skills
ln -s "$(pwd)" ~/.claude/skills/breakr
```

```powershell
# Windows (PowerShell, run inside the Breakr folder)
New-Item -ItemType Directory -Force "$HOME\.claude\skills" | Out-Null
New-Item -ItemType Junction -Path "$HOME\.claude\skills\breakr" -Target (Get-Location)
```

Then ask Claude something like *"audit this project for security issues"* or
*"use breakr on ./my-app"*. Claude will:

1. run the scanner
2. read the report
3. verify each finding in the code, using the guides in
   [`Breakr/Prompts/`](Breakr/Prompts)
4. give you a prioritised list of real issues and fixes

The full workflow is in [`Breakr/SKILL.md`](Breakr/SKILL.md).

### Command-line options

| Option | Description |
|---|---|
| `--agents A,B` | Run only these agents (default: picked automatically from the detected stack) |
| `--exclude PATTERN` | Skip matching files or folders. Can be repeated: `--exclude tests --exclude "legacy/*"` |
| `--include-ignored` | Also scan files marked `breakr: ignore-file` (see below) |
| `--format json\|markdown\|both` | Report format (default: `both`) |
| `--output-dir DIR` | Where reports are written (default: `Breakr/Reports/`) |
| `--min-severity LEVEL` | Hide findings below `CRITICAL` / `HIGH` / `MEDIUM` / `LOW` / `INFO` |
| `--min-confidence 0.5` | Hide findings below a confidence score |
| `--fail-on LEVEL` | Exit with code `2` if any finding is at or above `LEVEL` (for CI) |
| `--osv` | Check dependencies against live OSV.dev data (needs internet; sends only package names and versions) |
| `--quiet` | Print only the summary |
| `--no-color` | Plain output (also respects the `NO_COLOR` variable) |
| `--list-agents` | Describe every agent and exit |
| `--debug` | Show tracebacks if an agent crashes |
| `--version` | Print the version |

Exit codes:

- `0`: success
- `1`: error, such as a missing folder, an unknown agent, invalid arguments, or a report directory that can't be written
- `2`: the `--fail-on` threshold was reached, and nothing else

If one agent crashes, its error is recorded in the report and the rest of the audit continues.

### Run it in CI (GitHub Actions)

```yaml
- uses: actions/setup-python@v5
  with: { python-version: "3.12" }
- run: python Breakr/main.py . --fail-on HIGH --exclude Breakr --quiet
```

### Reports

Every run writes two reports:

- `security_report.json`, for tools and the AI
- `security_report.md`, for people

Each finding has:

- a stable ID (`BRK-001`, …)
- severity (CRITICAL → INFO) and a confidence score (0–1)
- file and line
- masked evidence
- an explanation of why it matters
- a recommended fix
- a CWE reference

The report also lists the agents that ran (and why each was chosen), the agents
that were skipped, and lines flagged by more than one agent.

### How Breakr keeps false positives low

- **Comments and string contents are ignored where it makes sense.** Commented-out code and documentation strings don't raise alarms, and line numbers stay correct.
- **Auth checks are traced across files.** A route counts as protected if the check is:
  - in the handler
  - at file level (`router.use(requireAuth)`, `APIRouter(dependencies=...)`)
  - in the file that mounts the router (`app.use('/admin', requireAdmin, adminRouter)`)
- **Public routes aren't flagged.** Login, signup, health checks and webhooks are recognised. Webhooks get their own signature check instead.
- **The `.env` check asks git.** It uses `git check-ignore`, which follows nested `.gitignore` files. A local `.env` that git ignores is treated as the right place for secrets.
- **Placeholders, version numbers, translation files and minified bundles are skipped.**
- **Intentional fixtures can opt out.** Put a comment line that is exactly `breakr: ignore-file` (`# breakr: ignore-file`, `// breakr: ignore-file`, ...) in a file's first 2 KB and Breakr skips it. It's listed under `ignored_files` in the report, and `--include-ignored` scans it anyway. Breakr's own vulnerable test fixtures use this, so a self-audit reports 0 findings.
- **A sanitiser lowers the severity.** If XSS or path findings sit in a file that uses DOMPurify, `secure_filename`, `basename` or similar, the finding is downgraded and you're asked to confirm the sanitiser covers that value.
- **It's tested on secure code too.** A "safe" test project must produce zero findings.

### Project layout

```
Breakr/
├── SKILL.md              # Skill definition: how the AI runs and reviews an audit
├── README.md             # Detailed Breakr documentation
├── main.py               # CLI entry point
├── Core/                 # Scanner (stack detection) and Head Agent (selection, dedupe, correlation)
├── Agents/               # The 10 agents + shared base class and route/auth detection
├── Models/               # Finding and ProjectProfile
├── Prompts/              # Triage guides the AI uses to verify each agent's findings
├── Reports/Reporter.py   # JSON and Markdown report writer
└── tests/                # Vulnerable + safe fixture projects and unit tests
```

### Tests

```bash
cd Breakr
python -m unittest discover -s tests -t . -v
```

The tests build two throwaway projects at runtime. One is deliberately
vulnerable and covers every agent. The other is secure and must produce
**zero** findings. Fake secrets are put together at runtime, so none are ever
committed.

### Adding an agent

1. Subclass `BaseBreaker` in `Breakr/Agents/` and define `Rule`s or a
   `scan_file()` method.
2. Register it in `AGENT_REGISTRY` in `Breakr/Agents/__init__.py`.
3. Write its triage guide in `Breakr/Prompts/`.
4. Add vulnerable and safe examples to `Breakr/tests/fixtures.py`.

There's a worked example in [Breakr/README.md](Breakr/README.md#adding-an-agent).

### Limitations

Breakr reads source code. It can't see:

- runtime config or environment variables in production
- cloud, IAM and network settings
- your auth provider's dashboard settings
- RLS policies that exist only in the Supabase dashboard
- business-logic flaws

Also:

- **Data flow:** analysis is heuristic and looks at one file at a time. The
  only cross-file tracing is for router mounting.
- **Django:** URLconf views are not analysed for auth.
- **Dependencies:** the built-in vulnerability list is a small, curated
  snapshot (about 40 high-impact advisories). Use `--osv`, `npm audit` or
  `pip-audit` for full coverage.

Use Breakr alongside dynamic testing and human review, not instead of them.

Only scan code you own or are authorised to test.

---

## Why Skills-For-AI?

General-purpose AI models are powerful, but specialized workflows can make them significantly more useful.

This repository focuses on building skills that give AI models:

- Specialized capabilities
- Structured workflows
- Deterministic tools
- Domain-specific reasoning
- Reliable and explainable outputs

Each skill is designed to solve a specific problem rather than trying to make one system do everything.

---

## Roadmap

More skills will be added over time across areas such as:

- Security
- Software development
- AI/ML
- Research
- Data analysis
- Productivity
- Agentic workflows

The goal is to build a growing ecosystem of practical, reusable skills for AI models.

---

## Author

**Ayush Sharma**

## License

[MIT](LICENSE)
