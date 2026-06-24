---
inclusion: auto
---

# Project Identity & Principles

## About This Project

FSx for ONTAP Cyber Resilience Patterns — multi-layered security reference architecture for Amazon FSx for NetApp ONTAP.

## Author Context

- Yoshiki Fujiwara (藤原 善基), NetApp CSA, AWS Community Builder (Storage)
- This is one of multiple interconnected repositories. Related repos:
  - `FSx-for-ONTAP-S3AccessPoints-Serverless-Patterns` (28 UC serverless patterns)
  - `FSx-for-ONTAP-Agentic-Access-Aware-RAG` (permission-aware RAG)
  - `fsxn-observability-integrations` (audit log → SIEM)
  - `blea-fsxn-usecase` (BLEA guest system patterns)

## Naming Rules (Absolute)

- First mention: **Amazon FSx for NetApp ONTAP**, thereafter **FSx for ONTAP**
- Forbidden: `FSxN`, bare `FSx`, `FSx ONTAP`, `FSx NetApp`
- S3 AP: **FSx for ONTAP S3 AP**
- Forbidden products: NetApp Workload Factory / NetApp Console / BlueXP → use native equivalents

## Neutrality Rules

- No vendor-versus framing. No "competing tools" / "beats X" / "X is inferior".
- Present TrendAI, Deep Instinct, and ONTAP native security as complementary layers with symmetric trade-off descriptions.
- Include "how to choose" guidance for each comparison.

## Public Repository Rules

- Never commit: real AWS account IDs, real IPs, SSH key paths, personal file paths, persona names.
- Use placeholders: `123456789012`, `10.0.x.x`, `<management-ip>`, `<your-key.pem>`.
- No persona names in commits/PRs — use role-based descriptions only.

## Code Standards

- Python 3.12 target (ARM64 Lambda)
- AWS CDK (TypeScript) for infrastructure
- Type hints on all functions, Google-style docstrings
- Tests: pytest + hypothesis
- CI: GitHub Actions with SHA-pinned actions, gitleaks, zizmor, OpenSSF Scorecard

## Documentation

- Bilingual: Japanese (primary) + English
- Code, variables, resource names: English
- Commit messages: English, conventional commits (`feat:`, `fix:`, `docs:`, `chore:`)
