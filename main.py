import sys
from pathlib import Path

from Core.Scanner import ProjectScanner
from Core.head_agent import HeadAgent
from Reports.Reporter import Reporter


def run_audit(project_path: str):

    target = Path(project_path).resolve()

    print("\nBREAKR")
    print("=" * 40)

    print("\nTarget:")
    print(target)

    # -------------------------
    # Validate target
    # -------------------------

    if not target.exists():

        print(
            "\nError: Target project does not exist."
        )

        return 1

    if not target.is_dir():

        print(
            "\nError: Target must be a directory."
        )

        return 1

    # -------------------------
    # Scan project
    # -------------------------

    scanner = ProjectScanner(
        str(target)
    )

    profile = scanner.create_profile()

    # -------------------------
    # Create Head Agent
    # -------------------------

    head = HeadAgent(profile)

    # -------------------------
    # Select agents
    # -------------------------

    agents = head.select_agents()

    print("\nProject Types:")

    if profile.project_types:

        for project_type in profile.project_types:
            print(f"- {project_type}")

    else:

        print("- None")

    print("\nTechnologies:")

    if profile.technologies:

        for technology in profile.technologies:
            print(f"- {technology}")

    else:

        print("- None")

    print("\nSelected Agents:")

    for agent in agents:
        print(f"- {agent}")

    # -------------------------
    # Run agents
    # -------------------------

    print("\nRunning security audit...")

    findings = head.run_agents()

    # -------------------------
    # Correlate findings
    # -------------------------

    finding_groups = (
        head.correlate_findings()
    )

    # -------------------------
    # Generate report
    # -------------------------

    reporter = Reporter()

    report_path = reporter.generate_json(
        findings,
        project_summary=head.get_project_summary(),
        finding_groups=finding_groups
    )

    # -------------------------
    # Results
    # -------------------------

    print("\nAudit complete.")
    print(
        f"Total findings: "
        f"{len(findings)}"
    )

    print(
        f"Correlated groups: "
        f"{len(finding_groups)}"
    )

    print(
        f"Report: "
        f"{report_path}"
    )

    # -------------------------
    # Findings summary
    # -------------------------

    if findings:

        print("\nFindings:")
        print("-" * 40)

        for finding in findings:

            print(
                f"[{finding.severity}] "
                f"{finding.title}"
            )

            print(
                f"  Agent: {finding.agent}"
            )

            print(
                f"  Location: "
                f"{finding.file}:"
                f"{finding.line}"
            )

            print(
                f"  Confidence: "
                f"{finding.confidence}"
            )

    else:

        print(
            "\nNo potential security issues "
            "were detected."
        )

    return 0


def main():

    if len(sys.argv) != 2:

        print(
            "\nUsage:"
        )

        print(
            "  python main.py <project_path>"
        )

        print(
            "\nExample:"
        )

        print(
            "  python main.py ./my-website"
        )

        return 1

    project_path = sys.argv[1]

    return run_audit(project_path)


if __name__ == "__main__":

    sys.exit(main())