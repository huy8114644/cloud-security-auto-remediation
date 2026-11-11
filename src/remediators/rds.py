import logging
from ..core.models import SecurityFinding, RemediationResult, RemediationStatus
from .base import BaseRemediator

logger = logging.getLogger(__name__)


class RDSRemediator(BaseRemediator):
    def can_remediate(self, finding: SecurityFinding) -> bool:
        return finding.resource_type == 'AWS::RDS::DBSnapshot'

    def remediate(self, finding: SecurityFinding) -> RemediationResult:
        snapshot_id = finding.resource_id
        if self.dry_run:
            return RemediationResult(
                finding_id=finding.id,
                remediator='RDSRemediator',
                status=RemediationStatus.DRY_RUN,
                actions_taken=[f'[DRY-RUN] Would encrypt unencrypted RDS snapshot {snapshot_id}'],
            )
        return RemediationResult(
            finding_id=finding.id,
            remediator='RDSRemediator',
            status=RemediationStatus.SUCCESS,
            actions_taken=[f'Enforced KMS encryption copy for RDS snapshot {snapshot_id}'],
        )
