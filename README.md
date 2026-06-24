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
│   └── observability/            # Audit log shipping & SIEM integration
├── shared/                       # Shared modules and utilities
├── security/                     # cfn-guard rules, security policies
├── docs/                         # Architecture diagrams, comparison docs
├── scripts/                      # Automation and deployment scripts
└── .github/workflows/            # CI/CD pipelines
```

## Getting Started

> Coming soon — Phase 0 (architecture design) in progress.

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

## Author

Yoshiki Fujiwara (藤原 善基) — NetApp CSA, AWS Community Builder (Storage)
