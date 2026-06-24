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
# Lint
make lint

# Test
make test

# Security scan
make security

# CDK synth
npx cdk synth

# Deploy (requires AWS credentials)
npx cdk deploy
```

## Coding Conventions

### Python
- Python 3.12, ARM64 Lambda target
- Type hints on all functions
- Google-style docstrings
- `from __future__ import annotations` at top
- Use `logging`, never `print()` in handlers

### TypeScript (CDK)
- AWS CDK v2
- Strict TypeScript
- Constructs follow L2/L3 patterns
- All resources tagged: `Project`, `Layer`, `Component`

### Naming
- Directories: kebab-case
- Python modules: snake_case
- CDK constructs/resources: PascalCase
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

- Framework: pytest + hypothesis
- Coverage target: 80%
- CDK: snapshot tests + fine-grained assertions
- Integration tests: tagged `e2e-*`, excluded from CI

## Documentation

- Bilingual: JA (primary) + EN
- Code/commits: English
- Conventional commits: `feat:`, `fix:`, `docs:`, `chore:`, `sec:`
