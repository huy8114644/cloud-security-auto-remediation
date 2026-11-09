from enum import Enum
from typing import Any, Dict, List, Optional
from datetime import datetime, timezone
from pydantic import BaseModel, Field


class FindingSeverity(str, Enum):
    LOW = "LOW"
    MEDIUM = "MEDIUM"
    HIGH = "HIGH"
    CRITICAL = "CRITICAL"


class RemediationStatus(str, Enum):
    SUCCESS = "SUCCESS"
    DRY_RUN = "DRY_RUN"
    SKIPPED = "SKIPPED"
    FAILED = "FAILED"


class SecurityFinding(BaseModel):
    id: str = Field(description="Unique finding identifier")
    title: str = Field(description="Finding title or alert summary")
    source: str = Field(description="Source system e.g. aws.guardduty, aws.securityhub, k8s.falco")
    severity: FindingSeverity
    resource_type: str = Field(
        description="Type of resource e.g. AWS::IAM::AccessKey, AWS::S3::Bucket, K8s::Pod"
    )
    resource_id: str = Field(description="Resource ARN or identifier")
    account_id: Optional[str] = Field(default=None, description="Cloud account ID")
    region: Optional[str] = Field(default="us-east-1", description="Cloud region")
    details: Dict[str, Any] = Field(default_factory=dict, description="Raw event metadata")
    created_at: datetime = Field(default_factory=lambda: datetime.now(timezone.utc))


class RemediationResult(BaseModel):
    finding_id: str
    remediator: str
    status: RemediationStatus
    actions_taken: List[str]
    details: Dict[str, Any] = Field(default_factory=dict)
    executed_at: datetime = Field(default_factory=lambda: datetime.now(timezone.utc))
