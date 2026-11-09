import logging
from ..core.models import SecurityFinding, RemediationResult, RemediationStatus
from .base import BaseRemediator

logger = logging.getLogger(__name__)


class KMSRemediator(BaseRemediator):
    def can_remediate(self, finding: SecurityFinding) -> bool:
        return finding.resource_type == "AWS::KMS::Key"

    def remediate(self, finding: SecurityFinding) -> RemediationResult:
        key_id = finding.resource_id
        if self.dry_run:
            return RemediationResult(
                finding_id=finding.id,
                remediator="KMSRemediator",
                status=RemediationStatus.DRY_RUN,
                actions_taken=[f"[DRY-RUN] Would disable KMS Key {key_id}"],
            )
        try:
            if self.client:
                self.client.disable_key(KeyId=key_id)
            return RemediationResult(
                finding_id=finding.id,
                remediator="KMSRemediator",
                status=RemediationStatus.SUCCESS,
                actions_taken=[f"Disabled compromised KMS Key {key_id}"],
            )
        except Exception as e:
            return RemediationResult(
                finding_id=finding.id,
                remediator="KMSRemediator",
                status=RemediationStatus.FAILED,
                actions_taken=[],
                details={"error": str(e)},
            )
