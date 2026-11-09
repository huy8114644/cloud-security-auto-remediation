import logging
from typing import List, Optional
from .models import SecurityFinding, RemediationResult, RemediationStatus
from ..remediators.base import BaseRemediator
from ..remediators.iam import IAMRemediator
from ..remediators.s3 import S3Remediator
from ..remediators.ec2_k8s import HostWorkloadRemediator
from ..notifiers.slack_telegram import SecurityAlertNotifier

logger = logging.getLogger(__name__)


class RemediationDispatcher:
    """
    Central event router matching security findings to appropriate remediators
    and dispatching audit telemetry notifications.
    """

    def __init__(
        self, dry_run: bool = False, remediators: Optional[List[BaseRemediator]] = None
    ) -> None:
        self.dry_run = dry_run
        self.remediators = remediators or [
            IAMRemediator(dry_run=dry_run),
            S3Remediator(dry_run=dry_run),
            HostWorkloadRemediator(dry_run=dry_run),
        ]
        self.notifier = SecurityAlertNotifier(dry_run=dry_run)

    def dispatch(self, finding: SecurityFinding) -> RemediationResult:
        logger.info(
            f"Processing finding {finding.id} (severity={finding.severity.value}, resource={finding.resource_type})"
        )

        for remediator in self.remediators:
            if remediator.can_remediate(finding):
                result = remediator.remediate(finding)
                self.notifier.notify(finding, result)
                return result

        logger.warning(f"No matching remediator for resource type: {finding.resource_type}")
        result = RemediationResult(
            finding_id=finding.id,
            remediator="None",
            status=RemediationStatus.SKIPPED,
            actions_taken=[f"No remediator configured for {finding.resource_type}"],
        )
        return result
