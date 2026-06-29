# FSx for ONTAP Cyber Resilience Patterns

Multi-layered cyber resilience patterns for Amazon FSx for NetApp ONTAP — combining storage-native security, AI-powered threat prevention, and event-driven automated response.

## Overview

This repository provides reference architectures and deployable patterns for protecting enterprise file data on Amazon FSx for NetApp ONTAP through defense-in-depth:

| Layer | Technology | Role |
|-------|-----------|------|
| **Storage-native** | ONTAP ARP, FPolicy, SnapLock, Tamperproof Snapshot, Multi-Admin Verification | Detection, immutability, approval control at the storage layer |
| **File scanning** | TrendAI Vision One — File Security | Real-time malware detection on file write (Vscan/ICAP or S3 AP) |
| **AI prevention** | Deep Instinct for NetApp ONTAP | Inference-based unknown threat prevention, zero-day protection |
| **Event-driven response** | FPolicy → EventBridge → Step Functions | Automated quarantine, notification, forensics workflows |
| **Audit & visibility** | ONTAP Audit Log → S3 AP → Lambda → SIEM | Full operation traceability, compliance |
| **Data protection** | Snapshot, SnapMirror, SnapLock, FlexClone | Ransomware recovery, evidence preservation |

## Project Structure

```
.
├── solutions/
│   ├── trendai-file-security/    # TrendAI Vision One File Security integration
│   ├── deep-instinct/            # Deep Instinct for NetApp ONTAP patterns
│   ├── ontap-native/             # ARP, FPolicy, SnapLock, MAV configurations
│   ├── event-driven-response/    # FPolicy → EventBridge → Step Functions
│   ├── observability/            # Security metrics & dashboard
│   └── shared/                   # ONTAP REST API client library
├── templates/                    # CloudFormation templates
│   ├── main.yaml                 # Root nested stack orchestrator
│   ├── network.yaml              # VPC, subnets, SGs, VPC Endpoints, Flow Logs
│   ├── storage.yaml              # FSx for ONTAP, KMS, ARP/FPolicy Custom Resource
│   ├── event-driven.yaml         # SQS, EventBridge, Step Functions, Lambda
│   ├── scanning.yaml             # TrendAI & Deep Instinct EC2 instances
│   └── observability.yaml        # CloudWatch Dashboard & Alarms
├── shared/tests/                 # Shared library unit tests
├── tests/                        # Lambda & template tests
├── security/                     # cfn-guard rules, security policies
├── docs/                         # Architecture diagrams, comparison docs
├── scripts/                      # Deployment & packaging automation
└── .github/workflows/            # CI/CD pipelines
```

## Getting Started

### Prerequisites

- AWS Account with permissions to create VPC, FSx, Lambda, Step Functions, SQS, EventBridge
- AWS CLI v2 configured
- Python 3.12+ (for cfn-lint, tests, Lambda development)
- make (for running project commands)

### Local Development (no AWS credentials required)

```bash
# Clone the repository
git clone https://github.com/Yoshiki0705/fsxn-cyber-resilience-patterns.git
cd fsxn-cyber-resilience-patterns

# Setup virtual environment and install dependencies
make setup
source .venv/bin/activate

# Configure git hooks (gitleaks + zizmor)
git config core.hooksPath .githooks

# Run linting (validates CloudFormation templates)
make lint

# Run tests (no AWS credentials needed)
make test

# Full pre-push validation
./scripts/validate-all.sh
```

### Deployment (requires AWS credentials)

```bash
# Deploy network stack to dev environment
./scripts/deploy.sh dev network

# Deploy all stacks
./scripts/deploy.sh dev

# Validate templates against AWS API
make validate
```

See [docs/architecture/overview.md](docs/architecture/overview.md) for the full architecture diagram.

## Why FSx for ONTAP for Cyber Resilience?

This project uses Amazon FSx for NetApp ONTAP as the demonstration platform because it provides unique storage-native security primitives (ARP, FPolicy, SnapLock, Tamperproof Snapshots, Multi-Admin Verification) that enable defense-in-depth at the storage layer — capabilities not available in general-purpose file or block storage.

**However, the defense-in-depth principles and event-driven response patterns in this project are broadly applicable.** Organizations using other storage services can adapt the concepts:

| This project demonstrates | Principle applies to |
|---------------------------|---------------------|
| ONTAP ARP (behavioral detection) | Any anomaly detection at the data layer |
| FPolicy → EventBridge | Any event-driven security automation |
| Vscan/ICAP integration | Any inline file scanning architecture |
| SnapLock (WORM) | Any immutable storage for evidence preservation |
| Step Functions quarantine | Any automated incident response workflow |

AWS-native alternatives for file-level security include:
- **Amazon GuardDuty Malware Protection** — agentless scanning for EBS, S3, ECS/EKS
- **AWS Backup** + **Vault Lock** — immutable backup retention
- **Amazon Macie** — data classification and sensitive data discovery
- **Amazon Inspector** — vulnerability scanning for compute workloads

This project focuses on the *file storage layer* (NAS workloads via NFS/SMB) where the above services have limited coverage, making FSx for ONTAP's native capabilities particularly relevant.

## Related Projects

- [FSx for ONTAP S3 Access Points Serverless Patterns](https://github.com/Yoshiki0705/FSx-for-ONTAP-S3AccessPoints-Serverless-Patterns)
- [FSx for ONTAP Agentic Access-Aware RAG](https://github.com/Yoshiki0705/FSx-for-ONTAP-Agentic-Access-Aware-RAG)
- [FSx for ONTAP Observability Integrations](https://github.com/Yoshiki0705/fsxn-observability-integrations)

## Security

This project follows supply-chain security best practices:
- GitHub Actions pinned to SHA hashes
- Secret detection via gitleaks
- Workflow security linting via zizmor
- OpenSSF Scorecard monitoring

## License

MIT

## Author & Disclosure

**Yoshiki Fujiwara** (藤原 善基) — NetApp Cloud Solutions Architect, AWS Community Builder (Storage)

> **Transparency note**: The author is employed by NetApp as a Cloud Solutions Architect specializing in Amazon FSx for NetApp ONTAP. This project is a personal community contribution and does not represent official NetApp or AWS product documentation. The security layer comparison is written with vendor neutrality in mind — all technologies are presented with symmetric trade-off descriptions, and the choice between options should be based on the reader's specific requirements and context. Feedback and alternative perspectives are welcome via Issues.
