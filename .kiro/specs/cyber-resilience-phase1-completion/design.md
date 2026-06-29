# Design Document: Phase 1 Completion

## Overview

Phase 1 completion のための技術設計。Lambda コードパッケージング、ONTAP 自動設定、Observability テンプレート、セキュリティ強化、デプロイ自動化の各コンポーネントの設計と相互関係を定義する。

## Architecture

```
┌──────────────────────────────────────────────────────────────────────┐
│                        Deployment Pipeline                            │
│  scripts/package-lambdas.sh → S3 Artifact Bucket → CFn Deploy        │
└──────────────────┬───────────────────────────────────────────────────┘
                   │
┌──────────────────▼───────────────────────────────────────────────────┐
│                        CloudFormation Stacks                          │
│                                                                      │
│  ┌─────────┐  ┌─────────┐  ┌──────────────┐  ┌──────────┐  ┌─────┐│
│  │ Network │→ │ Storage │→ │ Event-Driven │→ │ Scanning │→ │ Obs ││
│  │  Stack  │  │  Stack  │  │    Stack     │  │  Stack   │  │Stack││
│  └─────────┘  └────┬────┘  └──────┬───────┘  └──────────┘  └─────┘│
│                     │              │                                  │
│              Security_Config  Lambda Functions                        │
│              Custom Resource  (S3-referenced)                         │
└──────────────────────────────────────────────────────────────────────┘
                   │                    │
┌──────────────────▼────┐  ┌────────────▼──────────────────────────────┐
│  FSx for ONTAP        │  │  Event Processing Pipeline                │
│  ┌────────────────┐   │  │                                           │
│  │ ARP (dry_run)  │   │  │  SQS → Event Transformer → EventBridge   │
│  │ FPolicy (ICAP) │   │  │        → Step Functions → Quarantine      │
│  └────────────────┘   │  │        → SNS (alerts)                     │
└───────────────────────┘  └───────────────────────────────────────────┘
```

### Stack Dependency Graph
```
network ← storage ← event-driven ← scanning ← observability
                         ↑
                   package-lambdas (pre-step)
```

### Cross-Stack References

| Export Name Pattern | Source Stack | Consumer |
|--------------------|-------------|----------|
| `${Project}-${Env}-VpcId` | Network | Storage, Scanning |
| `${Project}-${Env}-SubnetSecurity1Id` | Network | Scanning |
| `${Project}-${Env}-SgFsxId` | Network | Storage |
| `${Project}-${Env}-SgLambdaId` | Network | Event-Driven |
| `${Project}-${Env}-VscanPrivateIp` | Scanning | Storage (FPolicy config) |
| `${Project}-${Env}-SecurityAlertTopicArn` | Event-Driven | Observability |
| `${Project}-${Env}-SecurityEventBusName` | Event-Driven | Observability |

## Components and Interfaces

### 1. Lambda Packaging System (`scripts/package-lambdas.sh`)

**Design Decision**: Shell script + `zip` (not SAM CLI). Reason: project uses vanilla CloudFormation, minimal dependencies.

**Logic**:
1. For each Lambda: copy source + shared/ to temp dir
2. Generate zip
3. Calculate content hash (sha256)
4. Skip S3 upload if same hash exists (idempotency)
5. Upload to `s3://${BUCKET}/${PREFIX}/${FUNCTION_NAME}-${HASH}.zip`

**S3 Bucket Requirements**:
- Server-Side Encryption (SSE-S3 or SSE-KMS) enabled
- Bucket Policy: Lambda execution roles only for `s3:GetObject`
- Versioning enabled (rollback support)

**Interface** (CloudFormation parameters):
```yaml
LambdaArtifactBucket: String  # S3 bucket name
LambdaArtifactPrefix: String  # Key prefix (default: lambda-packages/)
```

### 2. Security Config Custom Resource

**Interface** (Custom Resource properties):
```json
{
  "ManagementEndpoint": "string (DNS name)",
  "SecretArn": "string (Secrets Manager ARN)",
  "SvmUuid": "string",
  "VolumeUuids": ["string"],
  "FPolicyConfig": {
    "EngineName": "string",
    "PrimaryServers": ["string (IP)"],
    "Port": 1344,
    "EventName": "string",
    "Operations": ["write", "create"],
    "PolicyName": "string",
    "IsMandatory": false
  }
}
```

**Lifecycle**:
- `Create`: ARP dry_run + FPolicy engine/event/policy/enable
- `Update`: Compare properties, update changed resources
- `Delete`: Disable FPolicy (preserve ARP)

**Error Handling**:
| Error | Action |
|-------|--------|
| 409 Duplicate | Log warning, continue, SUCCESS |
| API unreachable | Retry 3x → FAILED |
| Timeout (>250s) | FAILED before 300s Lambda limit |
| Invalid credentials | FAILED with "Check Secrets Manager" |

### 3. Observability Stack (`templates/observability.yaml`)

**Resources**:
| Resource | Type | Purpose |
|----------|------|---------|
| SecurityDashboard | AWS::CloudWatch::Dashboard | Metrics visualization |
| MalwareBurstAlarm | AWS::CloudWatch::Alarm | ≥10 detections in 5 min |
| RansomwareAlarm | AWS::CloudWatch::Alarm | ARP alert ≥1 |
| ScanLatencyAlarm | AWS::CloudWatch::Alarm | p99 > 100ms |

**Dashboard JSON**: Inline via `Fn::Sub` (no runtime dependency). Same-region metrics only.

### 4. Security Hardening — Launch Template

**Design**: Wrap EC2 instances in Launch Template to enforce IMDSv2. Resolves cfn-lint schema limitation.

```yaml
LaunchTemplateData:
  MetadataOptions:
    HttpEndpoint: enabled
    HttpTokens: required
    HttpPutResponseHopLimit: 1
```

**VPC Flow Logs**: Added to network.yaml (Condition: CreateNewVpc)
- Destination: CloudWatch Logs
- Retention: 90 days
- KMS: Recommended for production (documented as trade-off)

**Lambda Concurrency**:
- QuarantineLambda: 10 (controlled execution)
- EventTransformerLambda: 50 (parallel event processing)

### 5. S3 AP Batch Scanning Queue

**Design**: Dedicated `BatchScanResultQueue` (separate from real-time `SecurityEventQueue`).

**Configuration**:
- `WaitTimeSeconds: 20` (Long Polling for cost)
- `VisibilityTimeout: 300`
- `KmsMasterKeyId: alias/aws/sqs`
- DLQ with same pattern as SecurityEventDlq

**Event Flow**:
```
S3 AP scan → SNS → BatchScanResultQueue → Scan_Result_Handler_Lambda → EventBridge
```

### 6. Deployment Orchestrator Enhancement

```bash
./scripts/deploy.sh <env> <stack|all>
# Stacks: package | network | storage | events | scanning | observability | all
# "all" uses `aws cloudformation wait` between dependent stacks
```

## Correctness Properties

### Property 1: Lambda Packaging Idempotency
Same source code produces same content hash; re-running packaging without code changes results in zero S3 uploads.
**Validates: Requirements 1.5**

### Property 2: Custom Resource Idempotency
Calling Create twice with same FPolicy name returns SUCCESS both times (409 handled gracefully).
**Validates: Requirements 2.5**

### Property 3: Event Normalization Totality
For all valid verdict payloads (malicious, suspicious, benign), the normalize→map pipeline produces a non-empty detail-type string from the defined set.
**Validates: Requirements 3.7**

### Property 4: Severity Mapping Totality
For all (classification ∈ {malicious, suspicious, benign}, confidence ∈ [0.0, 1.0]) pairs, _map_severity returns exactly one of CRITICAL, HIGH, MEDIUM, LOW, INFO.
**Validates: Requirements 3.8**
**Validates: Requirement 3.8**

## Error Handling

| Component | Error | Behavior |
|-----------|-------|----------|
| package-lambdas.sh | zip failure | Exit non-zero, halt deploy |
| package-lambdas.sh | S3 upload failure | Exit non-zero, halt deploy |
| Security Config CR | ONTAP 409 | Log, continue, SUCCESS |
| Security Config CR | ONTAP unreachable | Retry 3x, FAILED |
| Security Config CR | Timeout | FAILED at 250s |
| Event Transformer | EventBridge failure | Log, DLQ via SQS redrive |
| Quarantine Lambda | ONTAP API error | Raise → Step Functions catch → NotifyFailure state |
| Deploy script | Stack failure | Halt, report stack name + reason |

## Testing Strategy

| Test Type | Target | Framework | Location |
|-----------|--------|-----------|----------|
| Unit | verdict_handler | pytest + mock | `tests/test_verdict_handler.py` |
| Unit | scan_result_handler | pytest + mock | `tests/test_scan_result_handler.py` |
| Unit | security_metrics | pytest + mock | `tests/test_security_metrics.py` |
| Unit | dashboard_config | pytest | `tests/test_dashboard_config.py` |
| Unit | security_config_handler | pytest + mock | `tests/test_security_config_handler.py` |
| Property | _map_severity | hypothesis (50 runs) | `tests/test_verdict_handler.py` |
| Property | _normalize_verdict | hypothesis (50 runs) | `tests/test_scan_result_handler.py` |
| Integration | Event flow | pytest + mock (no AWS) | `tests/test_event_flow_integration.py` |
| Template | observability.yaml | pytest + cfn-lint | `tests/test_templates.py` |

**Shared Fixture**: `conftest.py` → `mock_env_vars` fixture for EVENT_BUS_NAME, FILE_SYSTEM_ID, ENVIRONMENT.

## Data Models

### Lambda Package Manifest (S3 key structure)
```
s3://${BUCKET}/${PREFIX}/
├── event-transformer-${GIT_HASH}.zip
├── quarantine-action-${GIT_HASH}.zip
├── verdict-handler-${GIT_HASH}.zip
└── scan-result-handler-${GIT_HASH}.zip
```

### Security Config Custom Resource Event (CloudFormation)
```json
{
  "RequestType": "Create|Update|Delete",
  "ResourceProperties": {
    "ManagementEndpoint": "management.fs-0123456789abcdef0.fsx.ap-northeast-1.amazonaws.com",
    "SecretArn": "arn:aws:secretsmanager:ap-northeast-1:123456789012:secret:fsxn-fsxadmin-XXXXXX",
    "SvmUuid": "uuid-string",
    "VolumeUuids": ["uuid-string"],
    "FPolicyConfig": {
      "EngineName": "cyber-resilience-scanner",
      "PrimaryServers": ["10.0.3.x"],
      "Port": 1344,
      "EventName": "file-write-scan",
      "Operations": ["write", "create"],
      "PolicyName": "malware-scan",
      "IsMandatory": false
    }
  }
}
```

### Normalized Security Event (EventBridge detail)
```json
{
  "fileSystemId": "fs-0123456789abcdef0",
  "filePath": "/volume/path/file.exe",
  "operation": "write",
  "verdict": "MALICIOUS",
  "scannerName": "trendai|deep-instinct",
  "severity": "CRITICAL|HIGH|MEDIUM|LOW|INFO",
  "timestamp": "2026-06-29T00:00:00Z"
}
```

| Aspect | Target |
|--------|--------|
| Lambda cold start | < 3s (Python 3.12 ARM64) |
| Event processing latency | < 5s (SQS → EventBridge) |
| Quarantine execution | < 30s |
| CI total time | < 5 minutes |
| Test coverage | ≥ 80% for `solutions/` |
| Lambda packaging | < 30s per function |
| Stack deployment (per stack) | < 10 minutes |
