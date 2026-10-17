import time
import traceback

from Agents import AGENT_REGISTRY, AGENTS_BY_NAME
from Agents.base_breaker import TEST_PATH
from Models.Finding import Finding, severity_rank
from Models.ProjectProfile import ProjectProfile


class HeadAgent:

    def __init__(self, project_profile: ProjectProfile, options=None):
        self.project_profile = project_profile

        # min_severity, min_confidence, osv, debug
        self.options = options or {}

        # Agent classes selected by the Head Agent
        self.agents = []

        # Agent name -> why it was selected
        self.selection_reasons = {}

        # Agent name -> {findings, seconds, error}
        self.agent_stats = {}

        # All findings returned by the agents
        self.findings = []

    def select_agents(self, requested=None):
        """
        Decide which security agents should run.

        By default each agent decides from the project profile whether it
        is relevant (e.g. SupabaseFirebaseBreaker only runs when Supabase
        or Firebase is detected). `requested` forces a specific list.
        """

        self.agents = []
        self.selection_reasons = {}

        if requested:

            for name in requested:

                agent = AGENTS_BY_NAME.get(name.strip().lower())

                if agent is None:
                    raise ValueError(
                        f"Unknown agent '{name}'. "
                        f"Available: {', '.join(a.name for a in AGENT_REGISTRY)}"
                    )

                if agent not in self.agents:
                    self.agents.append(agent)
                    self.selection_reasons[agent.name] = "requested"

        else:

            for agent in AGENT_REGISTRY:

                reason = agent.selection_reason(self.project_profile)

                if reason:
                    self.agents.append(agent)
                    self.selection_reasons[agent.name] = reason

        return [agent.name for agent in self.agents]

    def run_agents(self, progress=None):
        """
        Run all selected security agents and collect their findings.
        One failing agent never stops the audit.
        """

        self.findings = []

        for agent in self.agents:

            if progress:
                progress(agent.name)

            started = time.perf_counter()
            error = None
            findings = []

            try:
                breaker = agent(
                    self.project_profile.project_path,
                    files=self.project_profile.files,
                    options=self.options,
                )

                findings = breaker.scan()

            except Exception as exception:  # noqa: BLE001 - keep other agents running
                error = f"{type(exception).__name__}: {exception}"

                if self.options.get("debug"):
                    traceback.print_exc()

            self.agent_stats[agent.name] = {
                "findings": len(findings),
                "seconds": round(time.perf_counter() - started, 2),
                "error": error,
            }

            self.findings.extend(findings)

        self._downgrade_test_code(self.findings)
        self.findings = self._filter(self._deduplicate(self.findings))
        self.findings.sort(key=Finding.sort_key)

        return self.findings

    @staticmethod
    def _downgrade_test_code(findings):
        """Halve confidence for findings in tests, fixtures and examples."""

        for finding in findings:

            if not TEST_PATH.search(finding.file):
                continue

            finding.confidence = round(finding.confidence * 0.5, 2)
            finding.explanation += (
                " (Found in test/fixture/example code: lower risk unless "
                "this code ships to production.)"
            )

    @staticmethod
    def _deduplicate(findings):

        unique = {}

        for finding in findings:
            key = (finding.agent, finding.title, finding.file, finding.line)
            unique.setdefault(key, finding)

        return list(unique.values())

    def _filter(self, findings):

        min_severity = self.options.get("min_severity", "INFO")
        min_confidence = self.options.get("min_confidence", 0.0)

        return [
            finding
            for finding in findings
            if severity_rank(finding.severity) <= severity_rank(min_severity)
            and finding.confidence >= min_confidence
        ]

    def correlate_findings(self):
        """
        Group findings that point to the same file and line.

        Only locations flagged more than once are returned. Several
        agents agreeing on one line is a strong signal it needs review.
        This does not merge or delete findings.
        """

        groups = {}

        for finding in self.findings:
            groups.setdefault((finding.file, finding.line), []).append(finding)

        return [
            group
            for group in groups.values()
            if len(group) > 1
        ]

    def risk_level(self):
        """The most severe finding's severity, or NONE."""

        if not self.findings:
            return "NONE"

        return min(
            (finding.severity for finding in self.findings),
            key=severity_rank,
        )

    def get_agent_summary(self):

        return [
            {
                "name": agent.name,
                "description": agent.description,
                "reason": self.selection_reasons.get(agent.name),
                "prompt_file": f"Prompts/{agent.prompt_file}" if agent.prompt_file else None,
                **self.agent_stats.get(agent.name, {}),
            }
            for agent in self.agents
        ]

    def get_skipped_agents(self):

        return [
            agent.name
            for agent in AGENT_REGISTRY
            if agent not in self.agents
        ]

    def get_project_summary(self):
        """Return a simple summary of the scanned project."""

        return {
            "project_path": self.project_profile.project_path,
            "project_types": self.project_profile.project_types,
            "technologies": self.project_profile.technologies,
            "file_count": len(self.project_profile.files),
        }


if __name__ == "__main__":

    import sys

    from Core.Scanner import ProjectScanner

    profile = ProjectScanner(sys.argv[1] if len(sys.argv) > 1 else ".").create_profile()

    head = HeadAgent(profile)

    print("\nBREAKR HEAD AGENT")
    print("=" * 40)

    for name in head.select_agents():
        print(f"- {name} ({head.selection_reasons[name]})")

    findings = head.run_agents()

    print(f"\nTotal findings: {len(findings)}")

    for finding in findings:
        print(f"[{finding.severity}] {finding.title} - {finding.file}:{finding.line}")
