# Cloud Security Auto-Remediation (SOAR Engine)

[![Python SOAR CI](https://github.com/huy8114644/cloud-security-auto-remediation/actions/workflows/ci.yml/badge.svg)](https://github.com/huy8114644/cloud-security-auto-remediation/actions/workflows/ci.yml)
[![Python: 3.12](https://img.shields.io/badge/Python-3.12-3776ab.svg?logo=python&logoColor=white)](https://python.org)
[![Security: Pydantic v2](https://img.shields.io/badge/Validation-Pydantic%20v2-e92063.svg)](https://pydantic.dev)
[![Ruff: Checked](https://img.shields.io/badge/Code%20Style-Ruff-261230.svg)](https://astral.sh/ruff)
[![License: MIT](https://img.shields.io/badge/License-MIT-green.svg)](LICENSE)

Production-grade **Cloud Security Orchestration, Automation, and Response (SOAR)** engine written in modern Python. Designed for automated zero-human-delay threat containment across **AWS GuardDuty**, **AWS Security Hub**, and **Kubernetes Audit Logs**.

---

## 🏛️ Event-Driven SOAR Architecture

```mermaid
flowchart LR
    subgraph Sources ["1. Threat Detection Sources"]
        A[AWS GuardDuty<br/>Compromised IAM / EC2]
        B[AWS Security Hub<br/>Public S3 / Open SG]
        C[Falco / K8s Audit<br/>Crypto-miners / RCE]
    end

    subgraph Bus ["2. Event Ingestion"]
        A & B & C --> D[AWS EventBridge /<br/>Webhook Receiver]
    end

    subgraph Engine ["3. Python SOAR Dispatcher (AsyncIO + Pydantic v2)"]
        D --> E[Finding Validator<br/>Schema Validation]
        E --> F{Event Router}
    end

    subgraph Remediators ["4. Automated Remediation Playbooks"]
        F -->|IAM Compromise| G[IAMRemediator<br/>Deactivate Key + Quarantine Policy]
        F -->|Public S3| H[S3Remediator<br/>Enforce Block Public Access + SSE-KMS]
        F -->|RCE / Mining| I[HostRemediator<br/>Quarantine-SG + Pod Isolation]
    end

    subgraph Triage ["5. Real-Time Telemetry & Notification"]
        G & H & I --> J[Slack / Telegram<br/>Rich Security Card + Rollback Actions]
    end

    classDef dark fill:#0a192f,stroke:#4fd6a8,stroke-width:1.5px,color:#e6f1ff;
    class Sources,Bus,Engine,Remediators,Triage dark;
```

---

## 🛡️ Remediation Playbooks & MITRE ATT&CK Mapping

| Finding Type | Trigger / Source | MITRE ATT&CK | Automated Remediation Action |
|---|---|---|---|
| **Compromised IAM Key** | `UnauthorizedAccess:IAMUser/InstanceCredentialExfiltration` | T1552 - Unsecured Credentials | Deactivates Access Key via `UpdateAccessKey`, attaches inline `QuarantineDenyAll` policy |
| **Public S3 Bucket** | `S3.1 S3 Block Public Access` (Security Hub) | T1530 - Data from Cloud Storage | Enables all 4 S3 Block Public Access flags, enforces SSE-KMS encryption |
| **EC2 Cryptomining / C2** | `Trojan:EC2/DNSDataExfiltration` (GuardDuty) | T1496 - Resource Hijacking | Swaps active Security Groups with isolated `Quarantine-SG` (blocks all egress/ingress) |
| **Kubernetes Pod RCE** | `Terminal shell in production container` (Falco) | T1059 - Command and Scripting | Applies Zero-Trust network isolation policy, triggers forensic snapshot memory dump |

---

## 🚀 Key Features

- **Pydantic v2 Type Safety:** Strict validation of incoming cloud events with zero runtime parsing errors.
- **Dry-Run Mode Supported:** Safe testing in staging environments (`DRY_RUN=True`) simulating remediation actions before production rollout.
- **Defense in Depth:** Zero external binary dependencies; runs inside a multi-stage non-root container (UID 10001).
- **Incident Response Telemetry:** Structured JSON audit logs and rich Slack/Telegram webhook integration.

---

## 🛠️ Local Development & Testing

```bash
# Install package with developer dependencies
pip install -e ".[dev]"

# Run Ruff linter and formatter
ruff check .
ruff format --check .

# Run static type analysis with mypy
mypy src/

# Run complete pytest test suite with coverage
pytest --cov=src --cov-report=term-missing tests/

# Execute sample remediation dry-run
python -m src.main
```

---

## 📄 License
This project is licensed under the MIT License - see the [LICENSE](LICENSE) file for details.

