# FSx for ONTAP Cyber Resilience Patterns

Multi-layered cyber resilience patterns for Amazon FSx for NetApp ONTAP — combining storage-native security, AI-powered threat prevention, and event-driven automated response.

> **In plain terms**: If ransomware starts encrypting files on your NAS, this project detects it within seconds and automatically blocks the attacker's access at the storage layer — before a human responder can even open their laptop. It also creates a protected copy of your data at that moment, and can verify that copy is clean before you restore from it. Everything deploys as CloudFormation on AWS.

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

## Cyber Resilience Framework Mapping

This repository is designed against [NIST Cybersecurity Framework (CSF) 2.0](https://www.nist.gov/cyberframework), with additional alignment to [NIST SP 800-61r3](https://csrc.nist.gov/pubs/sp/800/61/r3/final) (Incident Handling) and [NIST IR 8374r1](https://csrc.nist.gov/pubs/ir/8374/r1/final) (Ransomware Risk Management). The table below maps each CSF 2.0 function to the specific components in this project and the companion [fsxn-observability-integrations](https://github.com/Yoshiki0705/fsxn-observability-integrations) repository.

### NIST CSF 2.0 Function Coverage

| CSF 2.0 Function | Status | This Repo | Companion Repo ([observability](https://github.com/Yoshiki0705/fsxn-observability-integrations)) | Gap / Organizational Responsibility |
|-------------------|:------:|-----------|---------------------|-----|
| **Govern (GV)** | ⚠️ | CloudFormation-as-code audit trail, cfn-guard compliance rules, `solutions/compliance/` evidence collection | CloudWatch Logs + SNS notification trails | Risk strategy, roles, board oversight remain organizational decisions; tooling provides evidence artifacts only |
| **Identify (ID)** | ✅ | Data classification matrix (`docs/`), asset tagging via CFn | Content-level PII scanner (Amazon Comprehend), schema-level field classification | Text/structured-data covered; Office/PDF extraction not yet implemented |
| **Protect (PR)** | ✅ | SnapLock (WORM), MAV (multi-admin verification), TrendAI inline scan, Deep Instinct AI prevention, export-policy/name-mapping hardening, KMS encryption | ONTAP Snapshot, export-policy, Tamperproof Snapshot | Full for storage-layer safeguards |
| **Detect (DE)** | ✅ | ARP/AI configuration (`solutions/ontap-native/`), FPolicy event capture, CloudWatch alarms (`templates/observability.yaml`) | EMS webhook pipeline (~30s), CloudWatch Log Alarm (~90s), FPolicy external server | Behavioral ML baseline delegated to SIEM (Datadog/Elastic/Splunk ML) |
| **Respond (RS)** | ✅ | Step Functions orchestration (quarantine, approval workflows), Security Hub integration | Lambda direct blocking (1.8s measured execution; +10-15s for cold start): name-mapping deny + export-policy deny + NACL deny + session disconnect + protective Snapshot, forensics dashboards (4 SIEMs) | Full for mitigation tooling (source-agnostic via SNS) ¹ |
| **Recover (RC)** | ⚠️ | SnapMirror lag monitoring (`templates/dr-replication.yaml`), DR replication patterns | Verified-clean recovery point (FlexClone + extension scan + verdict), TTL auto-unblock | Full restore rehearsal recommended via AWS Backup restore testing; RC.CO (stakeholder communication) is minimal |

> ¹ **Respond limitation**: SMB name-mapping deny is ineffective on NTFS security-style volumes (NTFS ACLs are evaluated directly without consulting the UNIX mapping). For NTFS volumes, alternative blocking mechanisms are needed (AD account disable, NTFS ACL removal, or network-layer NACL deny). See the [detailed framework mapping](docs/en/cyber-resilience-framework-mapping.md) for the full constraint matrix.

### NIST SP 800-61r3 Incident Handling Lifecycle

The project maps to SP 800-61's incident handling phases as follows:

```
┌────────────────────────────────────────────────────────────────────────────┐
│                        NIST SP 800-61r3 Lifecycle                           │
├──────────────┬──────────────┬──────────────────────┬──────────────────────┤
│  Preparation │  Detection & │  Containment,        │  Post-Incident       │
│              │  Analysis    │  Eradication &       │  Activity            │
│              │              │  Recovery            │                      │
├──────────────┼──────────────┼──────────────────────┼──────────────────────┤
│ • SnapLock   │ • ARP/AI     │ • SMB user block     │ • Forensics          │
│ • MAV        │ • FPolicy    │   (name-mapping)     │   dashboards         │
│ • TrendAI    │ • EMS webhook│ • NFS IP block       │ • Compliance         │
│   inline     │ • CloudWatch │   (export-policy     │   evidence pack      │
│   scan       │   Log Alarm  │   + NACL)            │ • Verified-clean     │
│ • Deep       │ • SIEM ML    │ • Session disconnect │   recovery point     │
│   Instinct   │   (delegated)│ • Protective         │ • Audit log          │
│ • Export-    │              │   Snapshot           │   retention          │
│   policy     │              │ • Step Functions     │ • Lessons learned    │
│   hardening  │              │   quarantine         │   (manual)           │
│ • KMS        │              │ • TTL auto-unblock   │                      │
│   encryption │              │                      │                      │
└──────────────┴──────────────┴──────────────────────┴──────────────────────┘
```

### NIST IR 8374r1 — Ransomware-Specific Outcomes

[NIST IR 8374r1](https://csrc.nist.gov/pubs/ir/8374/r1/final) maps ransomware-specific outcomes to CSF 2.0 functions. This project addresses the following ransomware outcomes:

| IR 8374r1 Outcome | Implementation |
|-------------------|---------------|
| **Detect ransomware file manipulation** | ARP/AI entropy + extension-change detection (ONTAP native, no learning period on 9.16.1+) |
| **Limit propagation** | Automated SMB/NFS access blocking within 2 minutes of detection |
| **Maintain immutable backups** | SnapLock WORM volumes, Tamperproof Snapshots (cannot be deleted by compromised admin) |
| **Verify backup integrity before restore** | FlexClone + isolated S3 AP scan for ransomware-associated extensions |
| **Rapid recovery** | FlexClone for isolated verification of a candidate Snapshot (space-efficient, copy-on-write); actual restore via `volume snapshot restore` or FlexClone promotion is a separate operation |
| **Evidence preservation** | Protective Snapshot at incident time + CloudWatch Logs audit trail (note: pre-action state not yet captured — see Governance Reporting Guidance below for chain-of-custody gap) |

### Additional Framework Alignment

| Framework | Relevant Components |
|-----------|-------------------|
| **AWS Well-Architected — Security Pillar** | IAM least-privilege (per-Lambda roles), encryption at rest (KMS), encryption in transit (TLS to ONTAP REST API), VPC isolation, Security Hub integration |
| **AWS Well-Architected — Reliability Pillar** | Multi-AZ FSx for ONTAP, SnapMirror cross-region replication, DLQ for failed response actions, CloudWatch alarms on pipeline health |
| **MITRE ATT&CK (Impact)** | T1486 (Data Encrypted for Impact) → ARP detection + automated blocking; T1490 (Inhibit System Recovery) → SnapLock + Tamperproof Snapshot; T1078 (Valid Accounts) → audit log pipeline for detection/traceability (visibility control, not prevention) |
| **CIS Controls v8** | Control 8 (Audit Log Management) → S3 AP audit pipeline; Control 11 (Data Recovery) → Snapshot + SnapMirror + verified recovery; Control 13 (Network Monitoring) → FPolicy + CloudWatch |

### Governance Reporting Guidance

When positioning this project's capabilities to a risk committee, compliance officer, or board:

- Frame as: "Automated Respond-phase containment (under 2 min) with Recover-phase pre-validation; Govern-phase maturity and the behavioral ML side of Detect are tracked separately"
- Do not frame as: "Ransomware protection is complete" — this covers one function deeply (Respond) and contributes to four others; Govern remains an organizational responsibility
- Evidence artifacts available: CloudFormation deployment records, CloudWatch Logs (trigger source, action taken, API response), DynamoDB verdict records (recovery verification), SNS notification trails
- Audit-trail limitation: the response pipeline logs post-action state, but does not currently capture pre-action state (the name-mapping/export-policy configuration before the block was applied)

> **Note on status markers**: ✅ indicates a capability is technically implemented and E2E-verified in this codebase. It does not represent compliance certification against any specific regulatory program (FedRAMP, ISMAP, HIPAA, PCI DSS, SOC 2, etc.). Treat these markers as one input when mapping your control requirements to available technical capabilities.

### Operational Considerations

Key caveats identified through multi-stakeholder review:

- **RTO/RPO**: This project does not define fixed RTO/RPO numbers — those are environment-specific and must be established by each deployment based on business requirements. The response module's measured E2E timing (under 2 min detect-to-block, under 3 min worst-case) provides a data point for your RPO calculation, not a guaranteed SLA.
- **False-positive handling**: Automated blocking carries inherent false-positive risk. The TTL auto-unblock companion stack (`automated-response-ttl.yaml`) limits lockout duration. Always test with non-production users first, and tune upstream detection rules before connecting them to the response pipeline.
- **Blast radius**: Both SMB name-mapping deny and NFS export-policy deny are **SVM-wide** — they affect all volumes and shares within the target SVM, not just the specified volume. Factor this into multi-tenant SVM designs.
- **Same-subnet NACL limitation**: NACL deny rules only apply to traffic crossing subnet boundaries. If the attacker's client and FSx for ONTAP ENIs are in the same subnet, the NACL has no effect — the export-policy deny (ONTAP-layer) is the only blocking mechanism in that scenario.
- **Data exfiltration gap**: ARP/AI detects file encryption (entropy + extension changes) but does not detect data exfiltration without encryption (e.g., pure data theft in double-extortion scenarios). FPolicy-based volume monitoring and SIEM behavioral analytics cover this gap partially.
- **Domain Admin bypass**: Users who are members of `FileSystemAdministratorsGroup` (typically Domain Admins) bypass name-mapping deny rules entirely. Always test blocking with non-admin users.
- **Privacy in response logs**: Automated response logs (CloudWatch Logs, SNS messages) contain personal data (username, domain, client IP). Apply appropriate access controls and retention policies.
- **Evidence tamper-resistance**: CloudWatch Logs in immutable retention mode provides tamper-resistant storage for response audit trails, supporting chain-of-custody requirements.
- **NFS client-side caching**: Export-policy deny takes effect immediately on the ONTAP server, but Linux NFS clients cache access decisions for up to 60 seconds (`actimeo` default). During this window, an already-mounted client may still perform I/O. The NACL deny rule (for cross-subnet scenarios) provides immediate packet-level blocking that bypasses client caching entirely.
- **Rollback/undo path**: If an automated block is a false positive, unblock via CLI (`automated-response-cli.sh unblock-smb --domain <CORP> --user <user>` or `unblock-nfs --ip <ip>`). The TTL auto-unblock stack also removes blocks after a configurable duration automatically.
- **NTFS volume alternatives**: For volumes using NTFS security style (where name-mapping deny is ineffective), consider: (1) disabling the user's AD account directly, (2) removing the user from NTFS share/file permissions, or (3) using NACL deny rules for network-layer blocking.
- **Zero Trust alignment**: This architecture implements several Zero Trust principles — deny-by-default (export-policy/name-mapping), verify explicitly (per-request ACL evaluation), assume breach (automated containment + evidence preservation). It does not implement microsegmentation at the file level.
- **AWS-specific implementation**: This project uses AWS-native services (Lambda, Step Functions, CloudFormation, CloudWatch, SNS, EventBridge). It is not directly portable to other cloud providers. The ONTAP REST API patterns are portable across any ONTAP deployment, but the orchestration and automation layer is AWS-specific.

For the complete function-by-function breakdown with alternative implementation paths and vendor-neutral comparison tables, see the [Cyber Resilience Capability Map](https://github.com/Yoshiki0705/fsxn-observability-integrations/blob/main/docs/en/cyber-resilience-capability-map.md) in the companion repository.

Detailed framework mapping documentation: [EN](docs/en/cyber-resilience-framework-mapping.md) | [JA](docs/ja/cyber-resilience-framework-mapping.md)

## Project Structure

```
.
├── solutions/
│   ├── trendai-file-security/    # TrendAI Vision One File Security integration
│   ├── deep-instinct/            # Deep Instinct for NetApp ONTAP patterns
│   ├── ontap-native/             # ARP, FPolicy, SnapLock, MAV configurations
│   ├── event-driven-response/    # FPolicy → EventBridge → Step Functions
│   ├── observability/            # Security metrics & dashboard
│   ├── siem/                      # Security Hub, Splunk/QRadar/CEF connectors
│   ├── compliance/               # Compliance evidence collection (SOC2/ISO27001)
│   └── shared/                   # ONTAP REST API client library
├── templates/                    # CloudFormation templates
│   ├── main.yaml                 # Root nested stack orchestrator
│   ├── network.yaml              # VPC, subnets, SGs, VPC Endpoints, Flow Logs
│   ├── storage.yaml              # FSx for ONTAP, KMS, ARP/FPolicy Custom Resource
│   ├── event-driven.yaml         # SQS, EventBridge, Step Functions, Lambda
│   ├── scanning.yaml             # TrendAI & Deep Instinct EC2 (single instance)
│   ├── scanning-ha.yaml          # Scanner ASG Multi-AZ (production HA)
│   ├── observability.yaml        # CloudWatch Dashboard & Alarms
│   ├── cost-scheduler.yaml       # Dev/staging instance stop/start automation
│   ├── dr-replication.yaml       # SnapMirror lag monitoring
│   ├── siem-integration.yaml     # Security Hub + SIEM + Compliance (optional)
│   ├── hub-aggregation.yaml      # Multi-account hub EventBridge bus
│   └── spoke-monitoring.yaml     # Multi-account spoke forwarding (StackSet)
├── benchmarks/                   # Performance benchmark suite
├── shared/tests/                 # Shared library unit tests
├── tests/                        # Lambda & template tests (285 tests)
├── security/                     # cfn-guard rules, security policies
├── docs/                         # Architecture, runbooks, deployment guides
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
# Deploy all core stacks (network → storage → events → scanning → observability)
./scripts/deploy.sh dev all

# Deploy individual stack
./scripts/deploy.sh dev network

# Package Lambda functions (required before events stack)
./scripts/deploy.sh dev package

# Deploy SIEM integration (optional)
aws cloudformation deploy --template-file templates/siem-integration.yaml \
  --stack-name fsxn-cyber-resilience-siem-dev --capabilities CAPABILITY_NAMED_IAM \
  --parameter-overrides EnableSecurityHub=true EnableSiemForwarder=false ...

# Deploy multi-account spoke (via StackSet or individual deploy)
aws cloudformation deploy --template-file templates/spoke-monitoring.yaml ...
```

See [docs/architecture/overview.md](docs/architecture/overview.md) for the full architecture diagram.
See [docs/quickstart-deployment.md](docs/quickstart-deployment.md) for detailed deployment guide with troubleshooting.
See [docs/deployment-guide-existing-fsxn.md](docs/deployment-guide-existing-fsxn.md) for existing environment setup.

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

| Repository | Relationship to This Repo | Key Components |
|-----------|---------------------------|----------------|
| [FSx for ONTAP Observability Integrations](https://github.com/Yoshiki0705/fsxn-observability-integrations) | **Companion** — implements detection and response primitives that plug into this repo's architecture layers | Automated access blocking (SMB/NFS), EMS webhook pipeline, CloudWatch Log Alarm, verified recovery point (FlexClone + scan), PII classification scanner, NIST CSF 2.0 capability map |
| [FSx for ONTAP S3 Access Points Serverless Patterns](https://github.com/Yoshiki0705/FSx-for-ONTAP-S3AccessPoints-Serverless-Patterns) | **Foundation** — S3 Access Point patterns used by both the audit log pipeline and the recovery verification workflow | S3 AP lifecycle management, presigned URL access, Lambda integration patterns |
| [FSx for ONTAP Agentic Access-Aware RAG](https://github.com/Yoshiki0705/FSx-for-ONTAP-Agentic-Access-Aware-RAG) | **Adjacent** — demonstrates permission-aware AI/RAG on the same FSx for ONTAP data that this repo protects | ACL-aware vector search, Bedrock Knowledge Bases, per-user authorization filtering |

### How the Observability Repo Connects

The [fsxn-observability-integrations](https://github.com/Yoshiki0705/fsxn-observability-integrations) repo provides the working implementations that connect to this repo's event-driven response layer:

- **Detect → Respond (under 2 minutes E2E)**: ARP/AI detection → EMS webhook → observability monitor → SNS → Lambda → ONTAP REST API blocking + protective Snapshot
- **Respond → Recover**: Protective Snapshot → FlexClone → isolated S3 AP scan → verified-clean verdict before restore
- **Identify**: Content-level PII classification via Amazon Comprehend (file contents, not filenames)

See [docs/en/companion-repos-integration.md](docs/en/companion-repos-integration.md) for the full layer mapping, deployment sequence, and cross-reference table.

### Related Articles

- [Automated Access Blocking for FSx for ONTAP — From Ransomware Detection to Storage-Layer Deny](https://dev.to/aws-builders/automated-access-blocking-for-fsx-for-ontap-from-ransomware-detection-to-storage-layer-deny-4l2g) (EN)
- [Amazon FSx for NetApp ONTAP の自動アクセス遮断 — ランサムウェア検知からストレージ層ブロックまで](https://hakobiya.hatenablog.com/entry/fsxn-automated-incident-response) (JA)

## Security

This project follows supply-chain security best practices:
- GitHub Actions pinned to SHA hashes
- Secret detection via gitleaks
- Workflow security linting via zizmor
- OpenSSF Scorecard monitoring
- Automated dependency updates via Renovate (`renovate.json`) — groups Python (`pip_requirements`) and GitHub Actions updates, keeps Actions SHA-pinned (`pinDigests`), gates major bumps behind Dependency Dashboard approval, and enables vulnerability/OSV alerts

> Renovate requires the [Renovate GitHub App](https://github.com/apps/renovate) to be enabled on this repository (separate one-time setup); the `renovate.json` in the repo root only configures its behavior.

## License

MIT

## Author & Disclosure

**Yoshiki Fujiwara** (藤原 善基) — NetApp Cloud Solutions Architect, AWS Community Builder (Storage)

> **Transparency note**: The author is employed by NetApp as a Cloud Solutions Architect specializing in Amazon FSx for NetApp ONTAP. This project is a personal community contribution and does not represent official NetApp or AWS product documentation. The security layer comparison is written with vendor neutrality in mind — all technologies are presented with symmetric trade-off descriptions, and the choice between options should be based on the reader's specific requirements and context. Feedback and alternative perspectives are welcome via Issues.
