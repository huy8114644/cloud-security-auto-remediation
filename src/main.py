import sys
import json
import logging
from .core.models import SecurityFinding, FindingSeverity
from .core.dispatcher import RemediationDispatcher

logging.basicConfig(level=logging.INFO, format="[%(asctime)s] %(levelname)s - %(name)s: %(message)s")
logger = logging.getLogger("soar-engine")


def run_sample_remediation() -> None:
    logger.info("Starting Cloud Security Auto-Remediation SOAR Engine...")
    dispatcher = RemediationDispatcher(dry_run=True)

    # Sample Incident 1: GuardDuty Compromised IAM Access Key
    iam_finding = SecurityFinding(
        id="finding-gd-8921",
        title="UnauthorizedAccess:IAMUser/InstanceCredentialExfiltration",
        source="aws.guardduty",
        severity=FindingSeverity.CRITICAL,
        resource_type="AWS::IAM::AccessKey",
        resource_id="AKIAIOSFODNN7EXAMPLE",
        details={"userName": "cicd-deployer-bot", "accessKeyId": "AKIAIOSFODNN7EXAMPLE"}
    )
    result_iam = dispatcher.dispatch(iam_finding)
    print(f"Result IAM: {result_iam.model_dump_json(indent=2)}")

    # Sample Incident 2: S3 Bucket Exposed Publicly
    s3_finding = SecurityFinding(
        id="finding-sh-4412",
        title="S3.1 S3 Block Public Access setting should be enabled",
        source="aws.securityhub",
        severity=FindingSeverity.HIGH,
        resource_type="AWS::S3::Bucket",
        resource_id="arn:aws:s3:::customer-invoices-backup",
        details={"bucketName": "customer-invoices-backup"}
    )
    result_s3 = dispatcher.dispatch(s3_finding)
    print(f"Result S3: {result_s3.model_dump_json(indent=2)}")


if __name__ == "__main__":
    run_sample_remediation()

