from datetime import datetime, timezone
from pathlib import Path
import json

from Core import BREAKR_VERSION
from Models.Finding import SEVERITY_ORDER


DEFAULT_OUTPUT_DIRECTORY = Path(__file__).resolve().parent


class Reporter:

    def __init__(self, output_directory=None):
        self.output_directory = Path(
            output_directory or DEFAULT_OUTPUT_DIRECTORY
        ).resolve()

        self.output_directory.mkdir(
            parents=True,
            exist_ok=True
        )

    # -------------------------
    # Shared report data
    # -------------------------

    @staticmethod
    def finding_ids(findings):
        """Stable IDs (BRK-001, ...) in report order."""

        return {
            id(finding): f"BRK-{index:03d}"
            for index, finding in enumerate(findings, start=1)
        }

    def build_report(
        self,
        findings,
        project_summary=None,
        finding_groups=None,
        agents=None,
        skipped_agents=None,
        risk_level=None,
    ):
        ids = self.finding_ids(findings)

        severity_counts = {
            severity: 0
            for severity in SEVERITY_ORDER
        }

        agent_counts = {}

        for finding in findings:

            severity = finding.severity.upper()

            if severity in severity_counts:
                severity_counts[severity] += 1

            agent_counts[finding.agent] = (
                agent_counts.get(finding.agent, 0) + 1
            )

        correlated_groups = []

        for index, group in enumerate(finding_groups or [], start=1):

            correlated_groups.append({
                "group_id": index,
                "file": group[0].file,
                "line": group[0].line,
                "finding_count": len(group),
                "agents": sorted({finding.agent for finding in group}),
                "finding_ids": [ids[id(finding)] for finding in group],
            })

        return {
            "tool": "Breakr",
            "version": BREAKR_VERSION,
            "generated_at": datetime.now(timezone.utc).isoformat(timespec="seconds"),

            "project": project_summary or {},

            "summary": {
                "risk_level": risk_level or "NONE",
                "total_findings": len(findings),
                "severity_counts": severity_counts,
                "agent_counts": agent_counts,
                "correlated_groups": len(correlated_groups),
            },

            "agents": agents or [],
            "skipped_agents": skipped_agents or [],

            "findings": [
                {"id": ids[id(finding)], **finding.to_dict()}
                for finding in findings
            ],

            "correlated_groups": correlated_groups,
        }

    # -------------------------
    # JSON
    # -------------------------

    def generate_json(
        self,
        findings,
        project_summary=None,
        finding_groups=None,
        filename="security_report.json",
        **extra
    ):
        report = self.build_report(
            findings,
            project_summary=project_summary,
            finding_groups=finding_groups,
            **extra
        )

        output_path = self.output_directory / filename

        with output_path.open("w", encoding="utf-8") as file:
            json.dump(report, file, indent=4)

        return output_path

    # -------------------------
    # Markdown
    # -------------------------

    def generate_markdown(
        self,
        findings,
        project_summary=None,
        finding_groups=None,
        filename="security_report.md",
        **extra
    ):
        report = self.build_report(
            findings,
            project_summary=project_summary,
            finding_groups=finding_groups,
            **extra
        )

        output_path = self.output_directory / filename

        output_path.write_text(
            self.render_markdown(report),
            encoding="utf-8",
        )

        return output_path

    @staticmethod
    def render_markdown(report):

        project = report["project"]
        summary = report["summary"]
        lines = []

        def add(text=""):
            lines.append(text)

        add("# Breakr Security Report")
        add()
        add(f"- **Project:** `{project.get('project_path', '')}`")
        add(f"- **Technologies:** {', '.join(project.get('technologies', [])) or 'none detected'}")
        add(f"- **Files scanned:** {project.get('file_count', 0)}")
        add(f"- **Generated:** {report['generated_at']} (Breakr {report['version']})")
        add(f"- **Overall risk:** **{summary['risk_level']}**")
        add()
        add("> Breakr is a static, pattern-based scanner. Every finding is a lead to verify, ")
        add("> not a confirmed vulnerability. Check each one in context before acting.")
        add()

        add("## Summary")
        add()
        add("| Severity | Count |")
        add("|---|---|")
        for severity, count in summary["severity_counts"].items():
            add(f"| {severity} | {count} |")
        add(f"| **Total** | **{summary['total_findings']}** |")
        add()

        add("## Agents")
        add()
        add("| Agent | Why it ran | Findings | Time |")
        add("|---|---|---|---|")
        for agent in report["agents"]:
            status = f"error: {agent['error']}" if agent.get("error") else agent.get("findings", 0)
            add(f"| {agent['name']} | {agent.get('reason') or ''} | {status} | {agent.get('seconds', 0)}s |")
        if report["skipped_agents"]:
            add()
            add(f"Not relevant to this project: {', '.join(report['skipped_agents'])}")
        add()

        add("## Findings")
        add()

        if not report["findings"]:
            add("No potential security issues were detected.")
            add()

        for severity in SEVERITY_ORDER:

            group = [
                finding
                for finding in report["findings"]
                if finding["severity"] == severity
            ]

            if not group:
                continue

            add(f"### {severity} ({len(group)})")
            add()

            for finding in group:
                add(f"#### {finding['id']}: {finding['title']}")
                add()
                add(f"- **Location:** `{finding['file']}:{finding['line']}`")
                add(f"- **Agent:** {finding['agent']} | **Confidence:** {finding['confidence']}"
                    + (f" | **{finding['cwe']}**" if finding.get("cwe") else ""))
                add()
                add("```text")
                add(finding["evidence"].replace("```", "'''"))
                add("```")
                add()
                add(f"**Why it matters:** {finding['explanation']}")
                add()
                add(f"**Fix:** {finding['recommendation']}")
                add()

        if report["correlated_groups"]:
            add("## Correlated locations")
            add()
            add("Lines flagged by more than one check. These are usually the best place to start.")
            add()
            for group in report["correlated_groups"]:
                add(f"- `{group['file']}:{group['line']}`: {', '.join(group['finding_ids'])} "
                    f"({', '.join(group['agents'])})")
            add()

        return "\n".join(lines)
