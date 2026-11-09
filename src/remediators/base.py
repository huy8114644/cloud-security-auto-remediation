from abc import ABC, abstractmethod
from typing import Any
from ..core.models import RemediationResult, SecurityFinding


class BaseRemediator(ABC):
    def __init__(self, dry_run: bool = False, client: Any | None = None) -> None:
        self.dry_run = dry_run
        self.client = client

    @abstractmethod
    def can_remediate(self, finding: SecurityFinding) -> bool:
        """Determines if this remediator can handle the given finding."""
        pass

    @abstractmethod
    def remediate(self, finding: SecurityFinding) -> RemediationResult:
        """Executes automated remediation workflow."""
        pass
