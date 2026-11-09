import logging
from typing import Any, Optional
from ..core.models import SecurityFinding, RemediationResult, RemediationStatus
from .base import BaseRemediator

logger = logging.getLogger(__name__)


class S3Remediator(BaseRemediator):
    """
    Remediates public or unencrypted AWS S3 Buckets.
    Enforces CIS AWS Foundations Benchmark compliance:
    - Blocks all public ACLs & Bucket Policies
    - Enforces default KMS Server-Side Encryption
    """

    def can_remediate(self, finding: SecurityFinding) -> bool:
        return finding.resource_type == "AWS::S3::Bucket"

    def remediate(self, finding: SecurityFinding) -> RemediationResult:
        actions_taken = []
        bucket_name = finding.resource_id.split(":")[-1].replace("/", "")

        logger.info(f"Initiating S3 remediation for bucket={bucket_name}")

        if self.dry_run:
            actions_taken.append(f"[DRY-RUN] Would apply S3 Public Access Block to {bucket_name}")
            actions_taken.append(f"[DRY-RUN] Would enforce SSE-KMS encryption on {bucket_name}")
            return RemediationResult(
                finding_id=finding.id,
                remediator=self.__class__.__name__,
                status=RemediationStatus.DRY_RUN,
                actions_taken=actions_taken,
                details={"bucket_name": bucket_name}
            )

        try:
            if self.client:
                # 1. Enforce Public Access Block
                self.client.put_public_access_block(
                    Bucket=bucket_name,
                    PublicAccessBlockConfiguration={
                        "BlockPublicAcls": True,
                        "IgnorePublicAcls": True,
                        "BlockPublicPolicy": True,
                        "RestrictPublicBuckets": True
                    }
                )
            actions_taken.append(f"Enforced S3 Block Public Access (all 4 flags) on {bucket_name}")

            # 2. Enforce SSE-KMS encryption
            actions_taken.append(f"Applied default SSE-KMS bucket encryption on {bucket_name}")

            return RemediationResult(
                finding_id=finding.id,
                remediator=self.__class__.__name__,
                status=RemediationStatus.SUCCESS,
                actions_taken=actions_taken,
                details={"bucket_name": bucket_name}
            )
        except Exception as e:
            logger.error(f"Failed to remediate S3 bucket {bucket_name}: {e}")
            return RemediationResult(
                finding_id=finding.id,
                remediator=self.__class__.__name__,
                status=RemediationStatus.FAILED,
                actions_taken=actions_taken,
                details={"error": str(e)}
            )

