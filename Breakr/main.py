import argparse
import os
import sys
from pathlib import Path

from Agents import AGENT_REGISTRY
from Core import BREAKR_VERSION
from Core.Scanner import ProjectScanner
from Core.head_agent import HeadAgent
from Models.Finding import SEVERITY_ORDER, severity_rank
from Reports.Reporter import DEFAULT_OUTPUT_DIRECTORY, Reporter


EXIT_OK = 0
EXIT_ERROR = 1
EXIT_THRESHOLD = 2

COLORS = {
    "CRITICAL": "\033[1;97;41m",
    "HIGH": "\033[1;91m",
    "MEDIUM": "\033[1;93m",
    "LOW": "\033[96m",
    "INFO": "\033[37m",
    "NONE": "\033[1;92m",
    "dim": "\033[2m",
    "bold": "\033[1m",
    "reset": "\033[0m",
}


class Output:
    """Terminal printing with optional colour."""

    def __init__(self, color: bool):
        self.color = color

        if color and os.name == "nt":
            os.system("")  # enables ANSI escape codes in the Windows console

    def paint(self, text, style):
        if not self.color:
            return str(text)
        return f"{COLORS[style]}{text}{COLORS['reset']}"

    def severity(self, severity):
        return self.paint(f"[{severity}]", severity)


def parse_arguments(argv=None):

    parser = argparse.ArgumentParser(
        prog="breakr",
        description=(
            "Breakr: a multi-agent static security auditor. Scans a project "
            "folder for leaked secrets, missing auth, injection, XSS, insecure "
            "config, vulnerable dependencies, weak crypto, Supabase/Firebase "
            "misconfigurations and unsafe file handling."
        ),
    )

    parser.add_argument(
        "project_path",
        nargs="?",
        help="Folder to audit (e.g. ./my-website)",
    )
    parser.add_argument(
        "--agents",
        help="Comma-separated agents to run instead of automatic selection "
             "(e.g. SecretBreaker,XSSBreaker)",
    )
    parser.add_argument(
        "--exclude",
        action="append",
        default=[],
        metavar="PATTERN",
        help="Skip files/folders matching this glob (repeatable), e.g. --exclude tests --exclude 'legacy/*'",
    )
    parser.add_argument(
        "--list-agents",
        action="store_true",
        help="List all agents and exit",
    )
    parser.add_argument(
        "--format",
        choices=["json", "markdown", "both"],
        default="both",
        help="Report format to write (default: both)",
    )
    parser.add_argument(
        "--output-dir",
        default=None,
        help=f"Where to write reports (default: {DEFAULT_OUTPUT_DIRECTORY})",
    )
    parser.add_argument(
        "--min-severity",
        type=str.upper,
        choices=SEVERITY_ORDER,
        default="INFO",
        help="Hide findings below this severity (default: INFO)",
    )
    parser.add_argument(
        "--min-confidence",
        type=float,
        default=0.0,
        help="Hide findings below this confidence, 0-1 (default: 0)",
    )
    parser.add_argument(
        "--fail-on",
        type=str.upper,
        choices=SEVERITY_ORDER,
        default=None,
        help="Exit with code 2 if any finding is at or above this severity (for CI)",
    )
    parser.add_argument(
        "--osv",
        action="store_true",
        help="Check dependencies against the live OSV.dev database (needs internet)",
    )
    parser.add_argument(
        "--quiet",
        action="store_true",
        help="Print only the summary, not every finding",
    )
    parser.add_argument(
        "--no-color",
        action="store_true",
        help="Disable coloured output",
    )
    parser.add_argument(
        "--debug",
        action="store_true",
        help="Print tracebacks if an agent crashes",
    )
    parser.add_argument(
        "--version",
        action="version",
        version=f"Breakr {BREAKR_VERSION}",
    )

    arguments = parser.parse_args(argv)

    if not arguments.list_agents and not arguments.project_path:
        parser.error("project_path is required (or use --list-agents)")

    return arguments


def list_agents(out: Output):

    print(out.paint("\nBREAKR AGENTS", "bold"))
    print("=" * 40)

    for agent in AGENT_REGISTRY:

        if agent.always_run:
            when = "always"
        else:
            triggers = sorted(agent.trigger_technologies) + list(agent.trigger_files)
            when = "when " + ", ".join(triggers[:6]) + (" ..." if len(triggers) > 6 else "")

        print(f"\n{out.paint(agent.name, 'bold')}")
        print(f"  {agent.description}")
        print(out.paint(f"  Runs: {when}", "dim"))

    return EXIT_OK


def run_audit(arguments):

    out = Output(
        color=(
            not arguments.no_color
            and "NO_COLOR" not in os.environ
            and sys.stdout.isatty()
        )
    )

    if arguments.list_agents:
        return list_agents(out)

    target = Path(arguments.project_path).resolve()

    print(out.paint(f"\nBREAKR {BREAKR_VERSION}", "bold"))
    print("=" * 40)

    print("\nTarget:")
    print(target)

    # -------------------------
    # Validate target
    # -------------------------

    if not target.exists():
        print("\nError: Target project does not exist.")
        return EXIT_ERROR

    if not target.is_dir():
        print("\nError: Target must be a directory.")
        return EXIT_ERROR

    output_directory = Path(
        arguments.output_dir or DEFAULT_OUTPUT_DIRECTORY
    ).resolve()

    # -------------------------
    # Scan project
    # -------------------------

    # Never scan our own previous reports.
    scanner = ProjectScanner(
        str(target),
        excluded_paths=[
            output_directory / "security_report.json",
            output_directory / "security_report.md",
        ],
        exclude_globs=arguments.exclude,
    )

    profile = scanner.create_profile()

    # -------------------------
    # Create Head Agent and select agents
    # -------------------------

    head = HeadAgent(
        profile,
        options={
            "min_severity": arguments.min_severity,
            "min_confidence": arguments.min_confidence,
            "osv": arguments.osv,
            "debug": arguments.debug,
        },
    )

    requested = (
        [name for name in arguments.agents.split(",") if name.strip()]
        if arguments.agents
        else None
    )

    try:
        agents = head.select_agents(requested)
    except ValueError as error:
        print(f"\nError: {error}")
        return EXIT_ERROR

    print(f"\nFiles: {len(profile.files)}")

    print("\nTechnologies:")
    print("- " + (", ".join(profile.technologies) or "None detected"))

    print("\nSelected Agents:")

    for agent in agents:
        print(f"- {agent} " + out.paint(f"({head.selection_reasons[agent]})", "dim"))

    skipped = head.get_skipped_agents()

    if skipped:
        print(out.paint(f"  Skipped (not relevant): {', '.join(skipped)}", "dim"))

    # -------------------------
    # Run agents
    # -------------------------

    print("\nRunning security audit...")

    findings = head.run_agents(
        progress=lambda name: print(out.paint(f"  > {name}", "dim"))
    )

    for name, stats in head.agent_stats.items():
        if stats["error"]:
            print(f"  ! {name} failed: {stats['error']} (other agents continued)")

    finding_groups = head.correlate_findings()

    # -------------------------
    # Generate reports
    # -------------------------

    reporter = Reporter(output_directory)

    report_data = dict(
        project_summary=head.get_project_summary(),
        finding_groups=finding_groups,
        agents=head.get_agent_summary(),
        skipped_agents=skipped,
        risk_level=head.risk_level(),
    )

    report_paths = []

    if arguments.format in {"json", "both"}:
        report_paths.append(reporter.generate_json(findings, **report_data))

    if arguments.format in {"markdown", "both"}:
        report_paths.append(reporter.generate_markdown(findings, **report_data))

    # -------------------------
    # Findings
    # -------------------------

    if findings and not arguments.quiet:

        print("\nFindings:")
        print("-" * 40)

        for number, finding in enumerate(findings, start=1):

            print(
                f"\n{out.severity(finding.severity)} "
                f"{out.paint(f'BRK-{number:03d}', 'dim')} "
                f"{finding.title}"
            )
            print(f"  Location:   {finding.file}:{finding.line}")
            print(f"  Agent:      {finding.agent}   Confidence: {finding.confidence}"
                  + (f"   {finding.cwe}" if finding.cwe else ""))
            print(out.paint(f"  Evidence:   {finding.evidence}", "dim"))

    elif not findings:
        print("\nNo potential security issues were detected.")

    # -------------------------
    # Summary
    # -------------------------

    counts = {severity: 0 for severity in SEVERITY_ORDER}

    for finding in findings:
        counts[finding.severity] = counts.get(finding.severity, 0) + 1

    print("\n" + "=" * 40)
    print("Audit complete.")
    print(f"Risk level: {out.paint(head.risk_level(), head.risk_level())}")
    print(
        "Findings: "
        + "  ".join(
            f"{severity} {counts[severity]}"
            for severity in SEVERITY_ORDER
        )
        + f"  (total {len(findings)})"
    )
    print(f"Correlated locations: {len(finding_groups)}")

    for path in report_paths:
        print(f"Report: {path}")

    # -------------------------
    # CI threshold
    # -------------------------

    if arguments.fail_on and any(
        severity_rank(finding.severity) <= severity_rank(arguments.fail_on)
        for finding in findings
    ):
        print(f"\nFailing: findings at or above {arguments.fail_on}.")
        return EXIT_THRESHOLD

    return EXIT_OK


def main(argv=None):

    # Avoid crashes when evidence contains characters the console can't encode.
    for stream in (sys.stdout, sys.stderr):
        try:
            stream.reconfigure(errors="replace")
        except (AttributeError, ValueError):
            pass

    return run_audit(parse_arguments(argv))


if __name__ == "__main__":

    sys.exit(main())
