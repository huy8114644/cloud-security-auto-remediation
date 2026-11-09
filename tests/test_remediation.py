from unittest.mock import MagicMock
from src.core.models import SecurityFinding, FindingSeverity, RemediationStatus
from src.core.dispatcher import RemediationDispatcher
from src.remediators.iam import IAMRemediator
from src.remediators.s3 import S3Remediator
from src.remediators.ec2_k8s import HostWorkloadRemediator
from src.notifiers.slack_telegram import SecurityAlertNotifier


def test_iam_remediator_dry_run():
    remediator = IAMRemediator(dry_run=True)
    finding = SecurityFinding(
        id="gd-101",
        title="Compromised Key",
        source="aws.guardduty",
        severity=FindingSeverity.CRITICAL,
        resource_type="AWS::IAM::AccessKey",
        resource_id="AKIA12345678",
        details={"userName": "alice"},
    )
    assert remediator.can_remediate(finding) is True

    result = remediator.remediate(finding)
    assert result.status == RemediationStatus.DRY_RUN
    assert len(result.actions_taken) == 2
    assert "Would deactivate IAM Access Key" in result.actions_taken[0]


def test_iam_remediator_live_execution():
    mock_iam_client = MagicMock()
    remediator = IAMRemediator(dry_run=False, client=mock_iam_client)
    finding = SecurityFinding(
        id="gd-102",
        title="Credential Exfiltration",
        source="aws.guardduty",
        severity=FindingSeverity.HIGH,
        resource_type="AWS::IAM::AccessKey",
        resource_id="AKIA99999999",
        details={"userName": "bob", "accessKeyId": "AKIA99999999"},
    )
    result = remediator.remediate(finding)
    assert result.status == RemediationStatus.SUCCESS
    mock_iam_client.update_access_key.assert_called_once_with(
        UserName="bob", AccessKeyId="AKIA99999999", Status="Inactive"
    )


def test_s3_remediator_live_execution():
    mock_s3_client = MagicMock()
    remediator = S3Remediator(dry_run=False, client=mock_s3_client)
    finding = SecurityFinding(
        id="sh-201",
        title="Public Bucket",
        source="aws.securityhub",
        severity=FindingSeverity.CRITICAL,
        resource_type="AWS::S3::Bucket",
        resource_id="arn:aws:s3:::prod-customer-data",
    )
    assert remediator.can_remediate(finding) is True

    result = remediator.remediate(finding)
    assert result.status == RemediationStatus.SUCCESS
    mock_s3_client.put_public_access_block.assert_called_once()


def test_host_workload_ec2_quarantine():
    mock_ec2_client = MagicMock()
    remediator = HostWorkloadRemediator(dry_run=False, client=mock_ec2_client)
    finding = SecurityFinding(
        id="gd-301",
        title="Crypto Miner Detected",
        source="aws.guardduty",
        severity=FindingSeverity.CRITICAL,
        resource_type="AWS::EC2::Instance",
        resource_id="i-0abcdef1234567890",
    )
    assert remediator.can_remediate(finding) is True

    result = remediator.remediate(finding)
    assert result.status == RemediationStatus.SUCCESS
    mock_ec2_client.modify_instance_attribute.assert_called_once_with(
        InstanceId="i-0abcdef1234567890", Groups=["sg-quarantine-isolated"]
    )


def test_dispatcher_routes_correctly():
    dispatcher = RemediationDispatcher(dry_run=True)
    finding = SecurityFinding(
        id="gd-401",
        title="Anomalous User Action",
        source="aws.guardduty",
        severity=FindingSeverity.HIGH,
        resource_type="AWS::IAM::AccessKey",
        resource_id="AKIA_SAMPLE_123",
    )
    result = dispatcher.dispatch(finding)
    assert result.status == RemediationStatus.DRY_RUN
    assert result.remediator == "IAMRemediator"


def test_dispatcher_skipped_unsupported_resource():
    dispatcher = RemediationDispatcher(dry_run=True)
    finding = SecurityFinding(
        id="misc-001",
        title="RDS Unencrypted",
        source="aws.securityhub",
        severity=FindingSeverity.LOW,
        resource_type="AWS::RDS::DBInstance",
        resource_id="db-unknown",
    )
    result = dispatcher.dispatch(finding)
    assert result.status == RemediationStatus.SKIPPED
    assert result.remediator == "None"


def test_slack_notifier_format():
    notifier = SecurityAlertNotifier(dry_run=False)
    finding = SecurityFinding(
        id="f-501",
        title="Exposed Database",
        source="aws.guardduty",
        severity=FindingSeverity.CRITICAL,
        resource_type="AWS::S3::Bucket",
        resource_id="arn:aws:s3:::my-bucket",
    )
    mock_result = MagicMock()
    mock_result.status.value = "SUCCESS"
    mock_result.actions_taken = ["Enforced S3 Public Access Block"]
    mock_result.executed_at.timestamp.return_value = 1700000000

    payload = notifier.format_slack_message(finding, mock_result)
    assert "attachments" in payload
    assert payload["attachments"][0]["color"] == "#ff0000"
