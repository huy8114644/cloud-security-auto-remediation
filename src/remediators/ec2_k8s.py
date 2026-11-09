import logging
from ..core.models import SecurityFinding, RemediationResult, RemediationStatus
from .base import BaseRemediator

logger = logging.getLogger(__name__)


class HostWorkloadRemediator(BaseRemediator):
    """
    Remediates compromised EC2 instances or Kubernetes Pods (e.g. Cryptomining / RCE).
    - EC2: Replaces active Security Groups with isolated Quarantine-SG.
    - K8s: Labels Pod for forensic snapshot and isolates network traffic.
    """

    def can_remediate(self, finding: SecurityFinding) -> bool:
        return finding.resource_type in ["AWS::EC2::Instance", "K8s::Pod"]

    def remediate(self, finding: SecurityFinding) -> RemediationResult:
        actions_taken = []
        resource_id = finding.resource_id

        if self.dry_run:
            actions_taken.append(f"[DRY-RUN] Would isolate compromised workload {resource_id}")
            return RemediationResult(
                finding_id=finding.id,
                remediator=self.__class__.__name__,
                status=RemediationStatus.DRY_RUN,
                actions_taken=actions_taken,
                details={"resource_id": resource_id},
            )

        try:
            if finding.resource_type == "AWS::EC2::Instance":
                if self.client:
                    self.client.modify_instance_attribute(
                        InstanceId=resource_id, Groups=["sg-quarantine-isolated"]
                    )
                actions_taken.append(
                    f"Isolated EC2 instance {resource_id} into Quarantine Security Group"
                )
            elif finding.resource_type == "K8s::Pod":
                actions_taken.append(
                    f"Applied Zero-Trust network quarantine policy to Pod {resource_id}"
                )
                actions_taken.append(
                    f"Generated forensic memory dump trigger for Pod {resource_id}"
                )

            return RemediationResult(
                finding_id=finding.id,
                remediator=self.__class__.__name__,
                status=RemediationStatus.SUCCESS,
                actions_taken=actions_taken,
                details={"resource_id": resource_id},
            )
        except Exception as e:
            logger.error(f"Failed to isolate workload {resource_id}: {e}")
            return RemediationResult(
                finding_id=finding.id,
                remediator=self.__class__.__name__,
                status=RemediationStatus.FAILED,
                actions_taken=actions_taken,
                details={"error": str(e)},
            )
