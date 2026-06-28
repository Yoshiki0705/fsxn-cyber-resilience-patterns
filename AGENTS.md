# AGENTS.md

> Project-specific instructions for AI coding agents working in this repository.

## Project Overview

FSx for ONTAP Cyber Resilience Patterns — multi-layered security reference architecture combining:
- ONTAP storage-native security (ARP, FPolicy, SnapLock, Multi-Admin Verification)
- TrendAI Vision One File Security (Vscan/ICAP, S3 AP integration)
- Deep Instinct for NetApp ONTAP (AI-powered zero-day prevention)
- Event-driven automated response (FPolicy → EventBridge → Step Functions)
- Audit & observability (integrates with fsxn-observability-integrations)

## Core Commands

```bash
# Lint (CloudFormation templates)
make lint

# Test (Python Lambda + template validation)
make test

# Security scan (cfn-guard + gitleaks)
make security

# Validate template
make validate

# Deploy (requires AWS credentials)
make deploy ENV=dev
```

## Coding Conventions

### Python
- Python 3.12, ARM64 Lambda target
- Type hints on all functions
- Google-style docstrings
- `from __future__ import annotations` at top
- Use `logging`, never `print()` in handlers

### CloudFormation (YAML)
- Templates in `templates/` directory
- Parameters in `parameters/` (per environment)
- cfn-lint for syntax validation
- cfn-guard for security/compliance rules
- All resources tagged: `Project`, `Layer`, `Component`
- Use `!Sub`, `!Ref`, `Fn::ImportValue` for cross-stack references
- Custom Resources (Lambda-backed) for ONTAP REST API calls

### Naming
- Directories: kebab-case
- Python modules: snake_case
- CloudFormation resource logical IDs: PascalCase
- Environment variables: UPPER_SNAKE_CASE

## Security Layers (Architecture)

```
┌─────────────────────────────────────────────────────────┐
│                    Application Layer                      │
│         (User access, IAM, AD, SVM isolation)           │
├─────────────────────────────────────────────────────────┤
│                   Network Layer                           │
│      (SG, NACL, VPC Endpoints, PrivateLink)             │
├─────────────────────────────────────────────────────────┤
│              File Scanning Layer                          │
│   TrendAI File Security │ Deep Instinct │ ONTAP Vscan   │
├─────────────────────────────────────────────────────────┤
│            Event-Driven Response Layer                    │
│    FPolicy → EventBridge → Step Functions → Actions      │
├─────────────────────────────────────────────────────────┤
│             Storage-Native Security Layer                 │
│   ARP │ SnapLock │ Tamperproof Snapshot │ MAV │ RBAC    │
├─────────────────────────────────────────────────────────┤
│               Data Protection Layer                       │
│     Snapshot │ SnapMirror │ FlexClone │ Backup          │
└─────────────────────────────────────────────────────────┘
```

## Neutrality Rule

This project compares multiple security technologies. Always:
- Present trade-offs symmetrically (include constraints of recommended options)
- Use "suited for" / "trade-off" framing, never "better than" / "beats"
- Include a "how to choose" section in every comparison document

## Testing

- Framework: pytest + hypothesis (Python Lambda functions)
- Coverage target: 80%
- CloudFormation: cfn-lint validation + cfn-guard compliance checks
- Template tests: pytest with cfn-lint programmatic API
- Integration tests: tagged `e2e-*`, excluded from CI

## Documentation

- Bilingual: JA (primary) + EN
- Code/commits: English
- Conventional commits: `feat:`, `fix:`, `docs:`, `chore:`, `sec:`
