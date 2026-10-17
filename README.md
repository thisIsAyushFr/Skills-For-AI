# Skills-For-AI

A collection of reusable skills built to extend the capabilities of AI models.

This repository is a growing library of specialized AI skills, each designed to give an AI model a structured workflow, tools, and capabilities for a specific task.

## Skills

### Breakr 🔐

**Security Auditing Skill**

Breakr is a security auditing skill for analyzing finished or AI-generated codebases for potential security issues.

Ten specialised agents detect and analyze:

- Hardcoded secrets and leaked API keys
- Missing server-side authentication and authorization
- Exposed API endpoints, IDOR and mass assignment
- SQL, NoSQL, command and code injection
- Cross-site scripting (XSS)
- Insecure configuration (debug mode, CORS, cookies, TLS)
- Vulnerable and unpinned dependencies
- Weak cryptography and JWT misuse
- Supabase / Firebase misconfigurations (service keys, RLS, open rules)
- Unsafe file uploads and path traversal

Breakr combines deterministic security analysis with AI-assisted interpretation to produce clear, structured security audits.

See [Breakr/README.md](Breakr/README.md) for usage and [Breakr/SKILL.md](Breakr/SKILL.md) for the skill workflow.

**Status:** v1.0.0

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
