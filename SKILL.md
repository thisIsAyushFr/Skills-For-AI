---
name: breakr
description: Security auditing skill for finished or AI-generated codebases. Use Breakr to scan a software project for potential hardcoded secrets, missing server-side authorization, and potentially exposed sensitive API endpoints, then review the structured security report.
---

# Breakr

Breakr is a security auditing tool designed to inspect finished or AI-generated software projects for potential security weaknesses.

Use Breakr when the user asks to:

- audit a codebase for security issues
- review an AI-generated or vibe-coded website for vulnerabilities
- scan a project for exposed secrets
- check API endpoints for security problems
- check for missing authorization
- perform a security-focused code review

Do not use Breakr for general code-quality reviews unless the user specifically wants security analysis.

---

## Core Workflow

When auditing a project:

1. Identify the target project directory.
2. Run Breakr against the target project.
3. Read the generated security report.
4. Review the findings and their evidence.
5. Explain the findings clearly to the user.
6. Distinguish potential findings from confirmed vulnerabilities.
7. Do not claim exploitability unless the available evidence supports it.

The current Breakr CLI is:

```bash
python main.py <project_path>