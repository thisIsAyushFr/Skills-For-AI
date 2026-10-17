# Skills-For-AI

AI skills that run real tools and then use the model's judgement on the results.

## Breakr

**[Breakr](Breakr/)** is a multi-agent security auditor. Ten specialised agents
scan a codebase for:

- leaked secrets
- missing auth and admin role checks
- exposed APIs, IDOR and mass assignment
- injection
- XSS
- insecure config
- vulnerable dependencies
- weak crypto
- Supabase/Firebase misconfigurations (service keys in the client, tables
  without RLS, open rules)
- unsafe file uploads

The AI then checks every lead against the code and returns a prioritised list
of verified fixes.

```bash
cd Breakr
python main.py ../path/to/your-app
```

- How it works, every agent, CLI options and CI usage: [Breakr/README.md](Breakr/README.md)
- How to use it as a Claude skill: [Breakr/SKILL.md](Breakr/SKILL.md)

Requires Python 3.11+. No dependencies.
