"""
Run from the Breakr folder:

    python -m unittest discover -s tests -t . -v
"""

import contextlib
import io
import json
import shutil
import tempfile
import unittest
from pathlib import Path

from Agents import AGENT_REGISTRY
from Agents.API_breaker import APIBreaker
from Agents.Auth_breaker import AuthBreaker
from Agents.Config_breaker import ConfigBreaker
from Agents.Crypto_breaker import CryptoBreaker
from Agents.Dependency_breaker import DependencyBreaker
from Agents.FileUpload_breaker import FileUploadBreaker
from Agents.Injection_breaker import InjectionBreaker
from Agents.Secret_breaker import SecretBreaker
from Agents.Supabase_firebase_breaker import SupabaseFirebaseBreaker
from Agents.XSS_breaker import XSSBreaker
from Agents.base_breaker import strip_comments, strip_strings
from Core.Scanner import ProjectScanner
from Core.head_agent import HeadAgent
from Reports.Reporter import Reporter
from tests.fixtures import (
    FAKE_GITHUB,
    FAKE_STRIPE_LIVE,
    SAFE_PROJECT,
    VULNERABLE_PROJECT,
    write_project,
)

import main


class ProjectTestCase(unittest.TestCase):

    files = {}

    @classmethod
    def setUpClass(cls):
        cls.root = Path(tempfile.mkdtemp(prefix="breakr-test-"))
        write_project(cls.root, cls.files)
        cls.profile = ProjectScanner(str(cls.root)).create_profile()
        cls.results = {}

    @classmethod
    def tearDownClass(cls):
        shutil.rmtree(cls.root, ignore_errors=True)

    def run_agent(self, agent):
        if agent not in self.results:
            self.results[agent] = agent(
                str(self.root), files=self.profile.files
            ).scan()
        return self.results[agent]

    def titles(self, agent):
        return {finding.title for finding in self.run_agent(agent)}

    def assertFound(self, agent, title, file=None):
        matches = [
            finding
            for finding in self.run_agent(agent)
            if title in finding.title and (file is None or finding.file == file)
        ]
        self.assertTrue(
            matches,
            f"{agent.name} did not report '{title}'"
            + (f" in {file}" if file else "")
            + f". Got: {sorted(self.titles(agent))}",
        )
        return matches[0]


class VulnerableProjectTests(ProjectTestCase):

    files = VULNERABLE_PROJECT

    # -------------------------
    # Scanner / Head Agent
    # -------------------------

    def test_detects_stack(self):
        for technology in ("Express", "Next.js", "React", "Flask", "Supabase", "Firebase", "Python", "Node.js"):
            self.assertIn(technology, self.profile.technologies)

    def test_all_agents_selected(self):
        head = HeadAgent(self.profile)
        self.assertEqual(
            set(head.select_agents()),
            {agent.name for agent in AGENT_REGISTRY},
        )

    # -------------------------
    # SecretBreaker
    # -------------------------

    def test_secrets(self):
        stripe = self.assertFound(SecretBreaker, "Stripe secret key")
        self.assertEqual(stripe.severity, "CRITICAL")
        self.assertNotIn(FAKE_STRIPE_LIVE, stripe.evidence, "secret must be masked")

        github = self.assertFound(SecretBreaker, "GitHub token")
        self.assertNotIn(FAKE_GITHUB, github.evidence)

        self.assertFound(SecretBreaker, "Hardcoded password", "settings.py")
        self.assertFound(SecretBreaker, "Environment file not ignored by git", ".env")

        database = self.assertFound(SecretBreaker, "Database URL with embedded password")
        self.assertEqual(database.severity, "HIGH")

    def test_package_names_are_not_tokens(self):
        # "jsonwebtoken": "8.5.1" must not look like a hardcoded token.
        self.assertFalse(
            any(f.file == "package.json" for f in self.run_agent(SecretBreaker))
        )

    def test_placeholder_secret_is_ignored(self):
        # SECRET_KEY = "changeme" is a weak default (ConfigBreaker), not a leak.
        self.assertFalse(
            any(f.file == "app.py" for f in self.run_agent(SecretBreaker))
        )

    # -------------------------
    # AuthBreaker
    # -------------------------

    def test_auth(self):
        unauthenticated = {
            (f.file, f.line)
            for f in self.run_agent(AuthBreaker)
            if f.title == "State-changing route without visible authentication"
        }
        self.assertIn(("server.js", 9), unauthenticated)     # POST /api/users
        self.assertIn(("server.js", 35), unauthenticated)    # POST /tools/traceroute
        self.assertIn(("upload.js", 7), unauthenticated)     # POST /upload
        self.assertTrue(any(f == "app/api/orders/route.ts" for f, _ in unauthenticated))
        self.assertTrue(any(f == "app/actions.ts" for f, _ in unauthenticated))

        # /login is intentionally public
        self.assertNotIn(("server.js", 24), unauthenticated)

        self.assertFound(AuthBreaker, "Admin route without role check", "server.js")
        self.assertFound(AuthBreaker, "Admin route without authentication or role check", "app.py")
        self.assertFound(AuthBreaker, "Admin route without authentication or role check", "pages/api/admin/stats.js")
        self.assertFound(AuthBreaker, "Webhook without signature verification")
        self.assertFound(AuthBreaker, "Authorization decided in client-side code")
        self.assertFound(AuthBreaker, "Auth token stored in localStorage")

    # -------------------------
    # APIBreaker
    # -------------------------

    def test_api(self):
        self.assertFound(APIBreaker, "Sensitive data endpoint without visible authentication", "server.js")
        self.assertFound(APIBreaker, "Sensitive data endpoint without visible authentication", "app.py")
        self.assertFound(APIBreaker, "Sensitive data endpoint without visible authentication", "app/api/orders/route.ts")
        self.assertFound(APIBreaker, "Mass assignment from request body")
        self.assertFound(APIBreaker, "Stack trace returned to client")
        self.assertFound(APIBreaker, "Login endpoint without rate limiting")

    # -------------------------
    # InjectionBreaker
    # -------------------------

    def test_injection(self):
        self.assertFound(InjectionBreaker, "SQL injection: query built with template literal", "server.js")
        self.assertFound(InjectionBreaker, "SQL injection: query built with f-string", "app.py")
        self.assertFound(InjectionBreaker, "NoSQL injection")
        self.assertFound(InjectionBreaker, "child_process.exec")
        self.assertFound(InjectionBreaker, "os.system")
        self.assertFound(InjectionBreaker, "Server-side template injection")
        self.assertFound(InjectionBreaker, "yaml.load")
        self.assertFound(InjectionBreaker, "pickle")

    # -------------------------
    # XSSBreaker
    # -------------------------

    def test_xss(self):
        self.assertFound(XSSBreaker, "dangerouslySetInnerHTML")
        self.assertFound(XSSBreaker, "URL fragment or query used in a DOM sink")
        self.assertFound(XSSBreaker, "Reflected XSS: request data written into the response")

    # -------------------------
    # ConfigBreaker
    # -------------------------

    def test_config(self):
        cors = self.assertFound(ConfigBreaker, "CORS allows any origin")
        self.assertEqual(cors.severity, "HIGH", "wildcard + credentials should escalate")
        self.assertFound(ConfigBreaker, "Debug mode enabled")
        self.assertFound(ConfigBreaker, "Flask debug server enabled")
        self.assertFound(ConfigBreaker, "TLS certificate verification disabled")
        self.assertFound(ConfigBreaker, "Session secret is a weak default")
        self.assertFound(ConfigBreaker, "Express app without security headers")
        self.assertFound(ConfigBreaker, "Container runs as root")

    # -------------------------
    # DependencyBreaker
    # -------------------------

    def test_dependencies(self):
        self.assertFound(DependencyBreaker, "Vulnerable dependency: next")
        self.assertFound(DependencyBreaker, "Vulnerable dependency: lodash")
        self.assertFound(DependencyBreaker, "Vulnerable dependency: express")
        self.assertFound(DependencyBreaker, "Vulnerable dependency: jsonwebtoken")
        self.assertFound(DependencyBreaker, "Vulnerable dependency: flask")
        self.assertFound(DependencyBreaker, "Vulnerable dependency: pyyaml")
        self.assertFound(DependencyBreaker, "Dependency range allows vulnerable django")
        self.assertFound(DependencyBreaker, "No lockfile")
        self.assertFound(DependencyBreaker, "Unpinned dependency: left-pad")
        self.assertFound(DependencyBreaker, "Unpinned Python dependencies")

    # -------------------------
    # CryptoBreaker
    # -------------------------

    def test_crypto(self):
        self.assertFound(CryptoBreaker, "Insecure randomness for a security value", "server.js")
        self.assertFound(CryptoBreaker, "Insecure randomness for a security value", "app.py")
        self.assertFound(CryptoBreaker, "Password hashed with a fast hash")
        self.assertFound(CryptoBreaker, "Hardcoded JWT signing secret")
        self.assertFound(CryptoBreaker, "Passwords compared in plaintext")
        self.assertFound(CryptoBreaker, "ECB cipher mode")
        self.assertFound(CryptoBreaker, "JWT decoded without signature verification")

    # -------------------------
    # SupabaseFirebaseBreaker
    # -------------------------

    def test_supabase_firebase(self):
        agent = SupabaseFirebaseBreaker
        self.assertFound(agent, "Supabase service_role key committed to the repository", "src/lib/supabase.js")
        self.assertFound(agent, "Secret exposed through a public browser env variable", ".env")
        self.assertFound(agent, "Supabase service_role key used in client-side code", "components/AdminPanel.jsx")
        self.assertFound(agent, "Table 'profiles' created without Row Level Security")
        self.assertFound(agent, "RLS policy lets anyone modify every row")
        self.assertFound(agent, "RLS policy lets anyone read every row")
        self.assertFound(agent, "Firebase rules in test mode")
        self.assertFound(agent, "Firebase rule allows public read")

        self.assertNotIn(
            "Table 'notes' created without Row Level Security",
            self.titles(agent),
        )

    # -------------------------
    # FileUploadBreaker
    # -------------------------

    def test_file_upload(self):
        self.assertFound(FileUploadBreaker, "Path traversal: request data used in a file operation")
        self.assertFound(FileUploadBreaker, "Uploaded file saved with the client's filename", "upload.js")
        self.assertFound(FileUploadBreaker, "Uploaded file saved with the client's filename", "app.py")
        self.assertFound(FileUploadBreaker, "File upload without a size limit", "upload.js")
        self.assertFound(FileUploadBreaker, "File upload without type validation", "app.py")
        self.assertFound(FileUploadBreaker, "Uploaded files served from a static directory")

    # -------------------------
    # Full pipeline
    # -------------------------

    def test_cli_writes_reports_and_fails_on_threshold(self):
        output = self.root / "_reports"

        code = main.main([
            str(self.root),
            "--output-dir", str(output),
            "--fail-on", "CRITICAL",
            "--quiet",
            "--no-color",
        ])

        self.assertEqual(code, main.EXIT_THRESHOLD)

        report = json.loads((output / "security_report.json").read_text(encoding="utf-8"))
        self.assertEqual(report["summary"]["risk_level"], "CRITICAL")
        self.assertEqual(len(report["agents"]), len(AGENT_REGISTRY))
        self.assertTrue(all(agent["error"] is None for agent in report["agents"]))
        self.assertTrue(report["findings"][0]["id"].startswith("BRK-"))

        markdown = (output / "security_report.md").read_text(encoding="utf-8")
        self.assertIn("# Breakr Security Report", markdown)

        # Raw secrets must never reach the report files.
        for secret in (FAKE_STRIPE_LIVE, FAKE_GITHUB):
            self.assertNotIn(secret, markdown)
            self.assertNotIn(secret, json.dumps(report))

    def test_min_severity_filter(self):
        head = HeadAgent(self.profile, options={"min_severity": "HIGH"})
        head.select_agents()
        findings = head.run_agents()
        self.assertTrue(findings)
        self.assertTrue(all(f.severity in {"CRITICAL", "HIGH"} for f in findings))


class SafeProjectTests(ProjectTestCase):
    """Secure code should produce no findings: guards against noisy rules."""

    files = SAFE_PROJECT

    def test_no_findings(self):
        head = HeadAgent(self.profile)
        head.select_agents()
        findings = head.run_agents()

        self.assertEqual(
            [],
            [f"{f.agent}: {f.title} @ {f.file}:{f.line} | {f.evidence}" for f in findings],
        )

        self.assertTrue(
            all(stats["error"] is None for stats in head.agent_stats.values())
        )


class HelperTests(unittest.TestCase):

    def test_strip_comments_keeps_offsets(self):
        source = 'const url = "https://x.io"; // password = "abc"\nlet a = 1; /* eval(x) */\n'
        stripped = strip_comments(source, Path("a.js"))

        self.assertEqual(len(source), len(stripped))
        self.assertEqual(source.count("\n"), stripped.count("\n"))
        self.assertIn('"https://x.io"', stripped)
        self.assertNotIn("password", stripped)
        self.assertNotIn("eval", stripped)

    def test_strip_python_comments(self):
        source = 'x = "a # not a comment"  # real comment\n'
        stripped = strip_comments(source, Path("a.py"))
        self.assertIn("a # not a comment", stripped)
        self.assertNotIn("real comment", stripped)

    def test_strip_strings(self):
        source = 'msg = "verify=False here"\nrequests.get(url, verify=False)\n'
        stripped = strip_strings(source, Path("a.py"))
        self.assertEqual(stripped.count("verify=False"), 1)

    def test_nested_gitignore_is_respected(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            write_project(root, {
                "backend/.gitignore": ".env\n",
                "backend/.env": "GITHUB_TOKEN=" + FAKE_GITHUB + "\n",
                "frontend/.env": "API_URL=http://localhost\n",
            })

            findings = SecretBreaker(str(root)).scan()
            files = {f.file for f in findings}

            self.assertNotIn("backend/.env", files, "ignored by backend/.gitignore")
            self.assertIn("frontend/.env", files, "not ignored anywhere")

    def test_minified_bundles_are_skipped(self):
        bundle = "var a=Math.random();const token=Math.random().toString(36);" * 200
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            write_project(root, {"assets/index-AbC123xY.js": bundle})
            self.assertEqual([], CryptoBreaker(str(root)).scan())

    def test_openrouter_key_named_correctly(self):
        key = "sk-" + "or-v1-" + "0123456789abcdef" * 4
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            write_project(root, {"chat.js": f'const KEY = "{key}";\n'})
            titles = {f.title for f in SecretBreaker(str(root)).scan()}
            self.assertEqual({"OpenRouter API key"}, titles)

    def test_unknown_agent_rejected(self):
        profile = ProjectScanner(".").create_profile()
        with self.assertRaises(ValueError):
            HeadAgent(profile).select_agents(["NopeBreaker"])

    def test_reporter_without_findings(self):
        with tempfile.TemporaryDirectory() as directory:
            path = Reporter(directory).generate_markdown([], project_summary={})
            self.assertIn("No potential security issues", path.read_text(encoding="utf-8"))


BREAKR_ROOT = Path(main.__file__).resolve().parent


def run_cli(*args):
    """Run the CLI quietly; return (exit code, captured stdout + stderr)."""

    output = io.StringIO()

    with contextlib.redirect_stdout(output), contextlib.redirect_stderr(output):
        try:
            code = main.main(list(args))
        except SystemExit as exit:
            code = exit.code

    return code, output.getvalue()


class IgnoreMarkerTests(unittest.TestCase):

    def test_self_audit_is_clean_but_fixtures_can_be_scanned(self):
        with tempfile.TemporaryDirectory() as output:

            # Default: the vulnerable fixture file is skipped, nothing else fires.
            code, _ = run_cli(str(BREAKR_ROOT), "--output-dir", output, "--quiet", "--no-color")
            report = json.loads((Path(output) / "security_report.json").read_text(encoding="utf-8"))

            self.assertEqual(code, main.EXIT_OK)
            self.assertEqual(report["project"]["ignored_files"], ["tests/fixtures.py"])
            self.assertEqual(
                [],
                [f"{f['agent']}: {f['title']} @ {f['file']}:{f['line']}" for f in report["findings"]],
            )

            # Explicitly opting in scans the fixtures again.
            run_cli(str(BREAKR_ROOT), "--output-dir", output, "--quiet", "--no-color", "--include-ignored")
            report = json.loads((Path(output) / "security_report.json").read_text(encoding="utf-8"))

            self.assertEqual(report["project"]["ignored_files"], [])
            self.assertTrue(any(f["file"] == "tests/fixtures.py" for f in report["findings"]))

    def test_marker_must_be_a_whole_comment_line(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            write_project(root, {
                "fixture.js": "// breakr: ignore-file\neval(userInput);\n",
                "fixture.py": "# breakr: ignore-file\neval(user_input)\n",
                "mentions.py": '# Files with a "breakr: ignore-file" marker are skipped\neval(user_input)\n',
            })

            scanner = ProjectScanner(str(root))
            profile = scanner.create_profile()

            self.assertEqual(sorted(profile.ignored_files), ["fixture.js", "fixture.py"])
            self.assertEqual(profile.files, ["mentions.py"])

            self.assertEqual(
                len(ProjectScanner(str(root), include_ignored=True).create_profile().files),
                3,
            )


class CLITests(ProjectTestCase):
    """End-to-end CLI behaviour, including error handling."""

    files = VULNERABLE_PROJECT

    def setUp(self):
        self.output = Path(tempfile.mkdtemp(prefix="breakr-out-"))

    def tearDown(self):
        shutil.rmtree(self.output, ignore_errors=True)

    def cli(self, *args):
        return run_cli(*args, "--output-dir", str(self.output), "--quiet", "--no-color")

    def test_missing_project_is_an_error(self):
        code, output = self.cli(str(self.root / "does-not-exist"))
        self.assertEqual(code, main.EXIT_ERROR)
        self.assertIn("does not exist", output)

    def test_file_instead_of_directory_is_an_error(self):
        code, output = self.cli(str(self.root / "server.js"))
        self.assertEqual(code, main.EXIT_ERROR)
        self.assertIn("must be a directory", output)

    def test_unknown_agent_is_an_error(self):
        code, output = self.cli(str(self.root), "--agents", "NopeBreaker")
        self.assertEqual(code, main.EXIT_ERROR)
        self.assertIn("Unknown agent", output)

    def test_bad_arguments_exit_1_not_2(self):
        # 2 is reserved for --fail-on, so CI can tell the two apart.
        self.assertEqual(run_cli()[0], main.EXIT_ERROR)
        self.assertEqual(run_cli(str(self.root), "--min-severity", "SEVERE")[0], main.EXIT_ERROR)

    def test_unwritable_output_directory_is_an_error(self):
        blocker = self.output / "not-a-directory"
        blocker.write_text("x", encoding="utf-8")

        code, output = run_cli(str(self.root), "--output-dir", str(blocker), "--quiet", "--no-color")

        self.assertEqual(code, main.EXIT_ERROR)
        self.assertIn("could not write reports", output)

    def test_list_agents_and_version(self):
        code, output = run_cli("--list-agents", "--no-color")
        self.assertEqual(code, main.EXIT_OK)
        for agent in AGENT_REGISTRY:
            self.assertIn(agent.name, output)

        code, output = run_cli("--version")
        self.assertEqual(code, 0)
        self.assertIn(main.BREAKR_VERSION, output)

    def test_json_only_format_and_agent_selection(self):
        code, _ = self.cli(str(self.root), "--format", "json", "--agents", "SecretBreaker,XSSBreaker")

        self.assertEqual(code, main.EXIT_OK)
        self.assertTrue((self.output / "security_report.json").exists())
        self.assertFalse((self.output / "security_report.md").exists())

        report = json.loads((self.output / "security_report.json").read_text(encoding="utf-8"))
        self.assertEqual([a["name"] for a in report["agents"]], ["SecretBreaker", "XSSBreaker"])
        self.assertTrue({f["agent"] for f in report["findings"]} <= {"SecretBreaker", "XSSBreaker"})

    def test_exclude_removes_files_from_the_scan(self):
        self.cli(str(self.root), "--exclude", "app.py", "--exclude", "supabase")
        report = json.loads((self.output / "security_report.json").read_text(encoding="utf-8"))
        files = {f["file"] for f in report["findings"]}

        self.assertNotIn("app.py", files)
        self.assertFalse(any(file.startswith("supabase/") for file in files))

    def test_safe_project_passes_fail_on(self):
        with tempfile.TemporaryDirectory() as directory:
            write_project(Path(directory), SAFE_PROJECT)
            code, _ = self.cli(directory, "--fail-on", "LOW")

        self.assertEqual(code, main.EXIT_OK)
        report = json.loads((self.output / "security_report.json").read_text(encoding="utf-8"))
        self.assertEqual(report["summary"]["risk_level"], "NONE")

    def test_crashing_agent_does_not_stop_the_audit(self):

        class CrashingBreaker(SecretBreaker):
            name = "CrashingBreaker"

            def scan(self):
                raise RuntimeError("boom")

        head = HeadAgent(self.profile)
        head.select_agents(["SecretBreaker"])
        head.agents.insert(0, CrashingBreaker)

        findings = head.run_agents()

        self.assertEqual(head.agent_stats["CrashingBreaker"]["error"], "RuntimeError: boom")
        self.assertIsNone(head.agent_stats["SecretBreaker"]["error"])
        self.assertTrue(any(f.agent == "SecretBreaker" for f in findings))


class SkillFilesTests(unittest.TestCase):
    """The AI half of the skill: SKILL.md and the triage prompts it points to."""

    def test_skill_frontmatter(self):
        text = (BREAKR_ROOT / "SKILL.md").read_text(encoding="utf-8")
        self.assertTrue(text.startswith("---\n"))

        frontmatter = text.split("---\n")[1]
        fields = dict(
            line.split(":", 1)
            for line in frontmatter.strip().splitlines()
        )

        self.assertEqual(fields["name"].strip(), "breakr")
        self.assertGreater(len(fields["description"].strip()), 50)

    def test_every_agent_has_a_triage_prompt(self):
        skill = (BREAKR_ROOT / "SKILL.md").read_text(encoding="utf-8")

        for agent in AGENT_REGISTRY:
            prompt = BREAKR_ROOT / "Prompts" / agent.prompt_file
            self.assertTrue(prompt.is_file(), f"{agent.name}: missing {prompt}")
            self.assertGreater(len(prompt.read_text(encoding="utf-8").strip()), 200)
            self.assertIn(f"Prompts/{agent.prompt_file}", skill)

        self.assertTrue((BREAKR_ROOT / "Prompts" / "Head.txt").is_file())


if __name__ == "__main__":
    unittest.main()
