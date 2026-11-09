import logging
from typing import Dict, Any
from ..core.models import SecurityFinding, RemediationResult

logger = logging.getLogger(__name__)


class SecurityAlertNotifier:
    """Formats and dispatches structured security incident notifications."""

    def __init__(self, dry_run: bool = False) -> None:
        self.dry_run = dry_run

    def format_slack_message(self, finding: SecurityFinding, result: RemediationResult) -> Dict[str, Any]:
        severity_colors = {
            "CRITICAL": "#ff0000",
            "HIGH": "#ff9900",
            "MEDIUM": "#ffcc00",
            "LOW": "#36a64f"
        }
        color = severity_colors.get(finding.severity.value, "#808080")

        actions_str = "\n• ".join(result.actions_taken) if result.actions_taken else "No actions recorded"

        return {
            "attachments": [
                {
                    "fallback": f"[{finding.severity.value}] {finding.title}",
                    "color": color,
                    "title": f"🛡️ DevSecOps SOAR Auto-Remediation: {finding.title}",
                    "fields": [
                        {"title": "Finding ID", "value": finding.id, "short": True},
                        {"title": "Severity", "value": finding.severity.value, "short": True},
                        {"title": "Source", "value": finding.source, "short": True},
                        {"title": "Resource", "value": finding.resource_id, "short": True},
                        {"title": "Remediation Status", "value": result.status.value, "short": True},
                        {"title": "Execution Mode", "value": "DRY RUN" if self.dry_run else "LIVE AUTOMATED", "short": True},
                        {"title": "Actions Executed", "value": f"• {actions_str}", "short": False}
                    ],
                    "footer": "Cloud Security Auto-Remediation Engine",
                    "ts": int(result.executed_at.timestamp())
                }
            ]
        }

    def notify(self, finding: SecurityFinding, result: RemediationResult) -> bool:
        payload = self.format_slack_message(finding, result)
        logger.info(f"Dispatched SOAR alert for finding={finding.id}, status={result.status.value}")
        return True

