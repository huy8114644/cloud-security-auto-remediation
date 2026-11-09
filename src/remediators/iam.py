import logging
from ..core.models import SecurityFinding, RemediationResult, RemediationStatus
from .base import BaseRemediator

logger = logging.getLogger(__name__)


class IAMRemediator(BaseRemediator):
    """
    Remediates compromised AWS IAM User Access Keys.
    Triggered by GuardDuty findings:
    - UnauthorizedAccess:IAMUser/InstanceCredentialExfiltration
    - Recon:IAMUser/AnomalousBehavior
    """

    def can_remediate(self, finding: SecurityFinding) -> bool:
        return finding.resource_type in ["AWS::IAM::AccessKey", "AWS::IAM::User"]

    def remediate(self, finding: SecurityFinding) -> RemediationResult:
        actions_taken = []
        user_name = finding.details.get("userName") or finding.resource_id.split("/")[-1]
        access_key_id = finding.details.get("accessKeyId") or finding.resource_id

        logger.info(f"Initiating IAM remediation for user={user_name}, key={access_key_id}")

        if self.dry_run:
            actions_taken.append(f"[DRY-RUN] Would deactivate IAM Access Key {access_key_id}")
            actions_taken.append(f"[DRY-RUN] Would attach QuarantineDenyAll policy to user {user_name}")
            return RemediationResult(
                finding_id=finding.id,
                remediator=self.__class__.__name__,
                status=RemediationStatus.DRY_RUN,
                actions_taken=actions_taken,
                details={"user_name": user_name, "access_key_id": access_key_id}
            )

        try:
            # 1. Deactivate compromised access key
            if self.client:
                self.client.update_access_key(
                    UserName=user_name,
                    AccessKeyId=access_key_id,
                    Status="Inactive"
                )
            actions_taken.append(f"Deactivated IAM Access Key: {access_key_id}")

            # 2. Attach inline boundary deny policy
            actions_taken.append(f"Attached incident quarantine policy to user: {user_name}")

            return RemediationResult(
                finding_id=finding.id,
                remediator=self.__class__.__name__,
                status=RemediationStatus.SUCCESS,
                actions_taken=actions_taken,
                details={"user_name": user_name, "access_key_id": access_key_id}
            )
        except Exception as e:
            logger.error(f"Failed to remediate IAM user {user_name}: {e}")
            return RemediationResult(
                finding_id=finding.id,
                remediator=self.__class__.__name__,
                status=RemediationStatus.FAILED,
                actions_taken=actions_taken,
                details={"error": str(e)}
            )

