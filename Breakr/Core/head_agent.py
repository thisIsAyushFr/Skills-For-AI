from Models.ProjectProfile import ProjectProfile
from Agents.Secret_breaker import SecretBreaker
from Agents.Auth_breaker import AuthBreaker
from Agents.API_breaker import APIBreaker
from Reports.Reporter import Reporter


class HeadAgent:

    def __init__(self, project_profile: ProjectProfile):
        self.project_profile = project_profile

        # Agents selected by the Head Agent
        self.agents = []

        # All findings returned by the agents
        self.findings = []

    def select_agents(self):
        """
        Decide which security agents should run.

        For the MVP, all three security agents are selected.
        """

        self.agents = [
            "SecretBreaker",
            "AuthBreaker",
            "APIBreaker"
        ]

        return self.agents

    def run_agents(self):
        """
        Run all selected security agents
        and collect their findings.
        """

        self.findings = []

        # -------------------------
        # SecretBreaker
        # -------------------------

        if "SecretBreaker" in self.agents:

            breaker = SecretBreaker(
                self.project_profile.project_path
            )

            findings = breaker.scan()

            self.findings.extend(findings)

        # -------------------------
        # AuthBreaker
        # -------------------------

        if "AuthBreaker" in self.agents:

            breaker = AuthBreaker(
                self.project_profile.project_path
            )

            findings = breaker.scan()

            self.findings.extend(findings)

        # -------------------------
        # APIBreaker
        # -------------------------

        if "APIBreaker" in self.agents:

            breaker = APIBreaker(
                self.project_profile.project_path
            )

            findings = breaker.scan()

            self.findings.extend(findings)

        return self.findings

    def correlate_findings(self):
        """
        Group findings that point to the same
        file and line.

        This does not merge or delete findings.
        It only identifies findings that may
        be related.
        """

        groups = {}

        for finding in self.findings:

            key = (
                finding.file,
                finding.line
            )

            if key not in groups:
                groups[key] = []

            groups[key].append(finding)

        return list(groups.values())

    def get_project_summary(self):
        """
        Return a simple summary of the scanned project.
        """

        return {
            "project_path": self.project_profile.project_path,
            "project_types": self.project_profile.project_types,
            "technologies": self.project_profile.technologies,
            "file_count": len(self.project_profile.files)
        }


if __name__ == "__main__":

    from Core.Scanner import ProjectScanner

    # -------------------------
    # Scan project
    # -------------------------

    scanner = ProjectScanner(".")

    profile = scanner.create_profile()

    # -------------------------
    # Create Head Agent
    # -------------------------

    head = HeadAgent(profile)

    # -------------------------
    # Select agents
    # -------------------------

    agents = head.select_agents()

    # -------------------------
    # Display project
    # -------------------------

    print("\nBREAKR HEAD AGENT")
    print("=" * 40)

    print("\nProject:")
    print(profile.project_path)

    print("\nTechnologies:")

    if profile.technologies:

        for technology in profile.technologies:
            print(f"- {technology}")

    else:

        print("- None")

    # -------------------------
    # Display selected agents
    # -------------------------

    print("\nSelected Agents:")

    for agent in agents:
        print(f"- {agent}")

    # -------------------------
    # Run agents
    # -------------------------

    print("\nRunning selected agents...")

    findings = head.run_agents()

    # -------------------------
    # Correlate findings
    # -------------------------

    finding_groups = head.correlate_findings()

    # -------------------------
    # Generate report
    # -------------------------

    reporter = Reporter()

    report_path = reporter.generate_json(
        findings,
        project_summary=head.get_project_summary(),
        finding_groups=finding_groups
    )

    print(
        f"\nSecurity report generated: "
        f"{report_path}"
    )

    # -------------------------
    # Display results
    # -------------------------

    print(
        f"\nTotal findings: {len(findings)}"
    )

    if findings:

        print("\nFindings:")
        print("-" * 40)

        for finding in findings:

            print(
                f"\n[{finding.severity}] "
                f"{finding.title}"
            )

            print(
                f"Agent: {finding.agent}"
            )

            print(
                f"Location: "
                f"{finding.file}:{finding.line}"
            )

            print(
                f"Confidence: "
                f"{finding.confidence}"
            )

            print(
                f"Evidence: "
                f"{finding.evidence}"
            )

        # -------------------------
        # Display correlated groups
        # -------------------------

        print("\n")
        print("CORRELATED FINDING GROUPS")
        print("-" * 40)

        for index, group in enumerate(
            finding_groups,
            start=1
        ):

            first_finding = group[0]

            print(
                f"\nGroup {index}: "
                f"{first_finding.file}:"
                f"{first_finding.line}"
            )

            for finding in group:

                print(
                    f"- {finding.agent}: "
                    f"{finding.title}"
                )

    else:

        print("\nNo findings detected.")

        print(
            "\nNo correlated finding groups."
        )