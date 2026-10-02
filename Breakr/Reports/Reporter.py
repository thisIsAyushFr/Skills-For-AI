import json
from pathlib import Path


class Reporter:

    def __init__(self, output_directory="Reports"):
        self.output_directory = Path(output_directory)

        self.output_directory.mkdir(
            parents=True,
            exist_ok=True
        )

    def generate_json(
        self,
        findings,
        project_summary=None,
        finding_groups=None,
        filename="security_report.json"
    ):
        output_path = (
            self.output_directory / filename
        )

        severity_counts = {
            "CRITICAL": 0,
            "HIGH": 0,
            "MEDIUM": 0,
            "LOW": 0,
            "INFO": 0
        }

        agent_counts = {}

        for finding in findings:

            severity = finding.severity.upper()

            if severity in severity_counts:
                severity_counts[severity] += 1

            agent = finding.agent

            agent_counts[agent] = (
                agent_counts.get(agent, 0) + 1
            )

        correlated_groups = []

        if finding_groups:

            for index, group in enumerate(
                finding_groups,
                start=1
            ):

                correlated_groups.append({
                    "group_id": index,
                    "file": group[0].file,
                    "line": group[0].line,
                    "finding_count": len(group),
                    "agents": [
                        finding.agent
                        for finding in group
                    ],
                    "findings": [
                        finding.to_dict()
                        for finding in group
                    ]
                })

        report = {
            "project": project_summary or {},

            "summary": {
                "total_findings": len(findings),
                "severity_counts": severity_counts,
                "agent_counts": agent_counts,
                "correlated_groups": len(
                    correlated_groups
                )
            },

            "findings": [
                finding.to_dict()
                for finding in findings
            ],

            "correlated_groups": correlated_groups
        }

        with output_path.open(
            "w",
            encoding="utf-8"
        ) as file:

            json.dump(
                report,
                file,
                indent=4
            )

        return output_path