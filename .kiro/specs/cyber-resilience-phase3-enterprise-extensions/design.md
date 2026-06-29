# Design Document: Phase 3 — Enterprise Extensions

## Overview

Phase 3 はエンタープライズ規模の統合を実現する。Security Hub / 3rd-party SIEM 連携、コンプライアンス証跡自動収集、マルチアカウント展開、パフォーマンスベンチマーク、および公開記事シリーズを対象とする。

## Architecture

```
┌───────────────────────────────────────────────────────────────────────┐
│                    Enterprise Architecture                             │
│                                                                       │
│  Hub Account (Security Monitoring)                                    │
│  ┌──────────────────────────────────────────────────────────┐         │
│  │ Security Hub (aggregated findings)                       │         │
│  │ SIEM Connector (Splunk/QRadar/CEF)                       │         │
│  │ Compliance Dashboard                                     │         │
│  │ Central EventBridge Bus (cross-account)                  │         │
│  └──────────────────────────────────────────────────────────┘         │
│       ▲              ▲              ▲                                  │
│       │              │              │  Cross-account EventBridge       │
│  ┌────┴────┐   ┌────┴────┐   ┌────┴────┐                            │
│  │ Spoke A │   │ Spoke B │   │ Spoke C │  Workload Accounts          │
│  │ FSx+Scan│   │ FSx+Scan│   │ FSx+Scan│                            │
│  └─────────┘   └─────────┘   └─────────┘                            │
│                                                                       │
│  ┌──────────────────────────────────────────────────────────┐         │
│  │ Compliance Collector (daily)                             │         │
│  │   ONTAP API → JSON report → S3 (Object Lock) → Alert    │         │
│  └──────────────────────────────────────────────────────────┘         │
│                                                                       │
│  ┌──────────────────────────────────────────────────────────┐         │
│  │ Benchmark Suite                                          │         │
│  │   Load Generator → FSx writes → measure pipeline latency │         │
│  └──────────────────────────────────────────────────────────┘         │
└───────────────────────────────────────────────────────────────────────┘
```

## Components and Interfaces

### 1. Security Hub Integration (`solutions/siem/security_hub_publisher.py`)

**Design**: EventBridge rule → Lambda → `securityhub:BatchImportFindings`

**ASFF Mapping**:
| EventBridge Field | ASFF Field |
|-------------------|------------|
| detail.severity | Severity.Label |
| detail.fileSystemId | Resources[0].Id |
| detail.filePath | Resources[0].Details.Other.filePath |
| detail-type | Title |
| source | ProductFields.source |

**FindingId**: `{region}/{account}/{fileSystemId}/{sha256(filePath+timestamp)}` — deduplication key.

**Interface**:
```python
def publish_to_security_hub(event: dict) -> dict:
    """Transform EventBridge event to ASFF and publish."""
```

### 2. Third-Party SIEM Connector (`solutions/siem/siem_forwarder.py`)

**Design**: EventBridge → SQS (batching) → Lambda → HTTPS POST to SIEM

**Output Formats**:
- Splunk HEC: `{"event": {...}, "sourcetype": "fsxn:security", "index": "main"}`
- QRadar LEEF: `LEEF:2.0|NetApp|FSxONTAP|1.0|MalwareDetected|...`
- Generic CEF: `CEF:0|FSxONTAP|CyberResilience|1.0|MalwareDetected|...`

**PII Redaction**:
```python
REDACT_FIELDS = ["clientIp", "userName"]  # Configurable
def redact_pii(event: dict, fields: list[str]) -> dict:
    """Replace specified fields with hashed values."""
```

**Batching**: SQS `MaximumBatchingWindowInSeconds: 30`, `BatchSize: 50`.

**Dead-letter**: S3 bucket with date-partitioned keys for failed deliveries.

### 3. Compliance Collector (`solutions/compliance/compliance_collector.py`)

**Design**: Daily EventBridge Scheduler → Lambda → ONTAP REST API queries → S3 report

**Controls Checked**:
| Control ID | Check | SOC2 Mapping | ISO27001 Mapping |
|-----------|-------|--------------|------------------|
| CR-ARP-001 | ARP enabled on all production volumes | CC6.1 | A.12.4 |
| CR-FP-001 | FPolicy active on all production SVMs | CC6.6 | A.12.4 |
| CR-SL-001 | SnapLock retention ≥ configured minimum | CC6.7 | A.12.3 |
| CR-ENC-001 | All volumes encrypted (at-rest) | CC6.1 | A.8.1 |
| CR-BKP-001 | Snapshot policy active | CC6.7 | A.12.3 |

**Report Storage**: S3 bucket with Object Lock (COMPLIANCE mode, 365-day retention).

**Interface**:
```python
@dataclass
class ComplianceResult:
    timestamp: str
    control_id: str
    expected_state: str
    actual_state: str
    compliant: bool
    evidence_detail: dict
    soc2_mapping: str
    iso27001_mapping: str
```

### 4. Multi-Account Pattern

**Hub-Spoke Design**:
- **Hub**: Central account with Security Hub, aggregated EventBridge bus, SIEM connector
- **Spoke**: Workload accounts with FSx for ONTAP + Phase 1/2 stacks

**Cross-Account Mechanism**: EventBridge cross-account event bus rules
```yaml
# Spoke-side rule (StackSet deployed)
SpokeToHubRule:
  Type: AWS::Events::Rule
  Properties:
    EventBusName: !Ref LocalSecurityBus
    EventPattern:
      source: [{prefix: "fsxn.cyber-resilience"}]
    Targets:
      - Id: HubBus
        Arn: !Sub "arn:${AWS::Partition}:events:${HubRegion}:${HubAccountId}:event-bus/${HubBusName}"
        RoleArn: !GetAtt CrossAccountEventRole.Arn
```

**StackSet Template**: `templates/spoke-monitoring.yaml` — deployed via Organizations StackSet.

### 5. Benchmark Suite (`benchmarks/`)

**Design**: Python scripts using boto3 + paramiko (SSH to FSx client) for file write generation.

**Directory Structure**:
```
benchmarks/
├── README.md              # Methodology, caveats, environment description
├── run_benchmark.py       # Orchestrator
├── load_generator.py      # File write generation via NFS
├── latency_collector.py   # CloudWatch metric collection
├── results/               # JSON result files (gitignored)
└── analysis/              # Jupyter notebooks for visualization
```

**Measurement Points**:
1. File write → ICAP scan complete (scan latency)
2. EventBridge event → Step Functions start (pipeline latency)
3. Step Functions start → export policy restricted (quarantine latency)
4. Max throughput before DLQ overflow (pipeline capacity)

**Cost Estimation Output**: Each benchmark result includes `estimated_cost_usd` field.

### 6. Article Series

**Article Plan**:
| # | Title | Focus |
|---|-------|-------|
| 1 | Multi-Layered Cyber Resilience for FSx for ONTAP | Architecture overview |
| 2 | ONTAP Native Security: ARP + FPolicy Deep Dive | Storage-layer protection |
| 3 | Event-Driven Ransomware Response with Step Functions | Automation patterns |
| 4 | Operating FSx for ONTAP Security at Scale | Lessons learned, benchmarks |

**Review Process**: Each article → role-based review (Storage Specialist + DevOps/SRE) → publish.

## Correctness Properties

### Property 1: ASFF Deduplication
The same file path + timestamp combination SHALL always produce the same FindingId, ensuring Security Hub deduplication works correctly.
**Validates: Requirements 1.5**

### Property 2: PII Redaction Completeness
For all events passing through the SIEM connector with redaction enabled, no configured PII field SHALL appear in the output payload in cleartext.
**Validates: Requirements 2.7**

### Property 3: Compliance Report Consistency
For a given ONTAP state snapshot, running the Compliance Collector twice SHALL produce identical compliance results (deterministic).
**Validates: Requirements 3.1**

### Property 4: Cross-Account Isolation
Spoke-to-hub IAM roles SHALL have ONLY events:PutEvents permission on the hub event bus — no other hub account access.
**Validates: Requirements 4.5**

## Data Models

### ASFF Finding (Security Hub)
```json
{
  "SchemaVersion": "2018-10-08",
  "Id": "{region}/{account}/{fsId}/{hash}",
  "ProductArn": "arn:aws:securityhub:{region}:{account}:product/{account}/fsxn-cyber-resilience",
  "GeneratorId": "fsxn-cyber-resilience-{scanner}",
  "Types": ["Software and Configuration Checks/Vulnerabilities/Malware"],
  "Severity": {"Label": "CRITICAL"},
  "Title": "MalwareDetected on FSx for ONTAP volume",
  "Resources": [{"Type": "Other", "Id": "fs-0123456789abcdef0"}]
}
```

### Compliance Report (S3)
```
s3://compliance-bucket/reports/{year}/{month}/{day}/compliance-{env}-{timestamp}.json
```

### Benchmark Result
```json
{
  "benchmark_id": "scan-latency-1000-fpm",
  "timestamp": "2026-07-15T10:00:00Z",
  "environment": {"instance_type": "c6g.xlarge", "fsx_throughput": "512 MBps"},
  "results": {"p50_ms": 12, "p95_ms": 25, "p99_ms": 42, "max_ms": 85},
  "estimated_cost_usd": 3.50,
  "caveats": ["Single AZ", "Synthetic workload", "Not production estimate"]
}
```

## Error Handling

| Component | Error | Behavior |
|-----------|-------|----------|
| Security Hub Publisher | BatchImportFindings failure | Retry 3x → DLQ |
| SIEM Forwarder | HTTPS timeout | Exponential backoff → S3 dead-letter |
| SIEM Forwarder | Auth failure | Alert + disable (prevent credential lockout) |
| Compliance Collector | ONTAP API timeout | Retry → report "UNKNOWN" state |
| Cross-Account Event | Permission denied | CloudWatch alarm in spoke |
| Benchmark | Timeout | Partial results saved, marked incomplete |

## Testing Strategy

| Test Type | Target | Notes |
|-----------|--------|-------|
| Unit | security_hub_publisher | ASFF format validation, dedup logic |
| Unit | siem_forwarder | Format conversion (Splunk/QRadar/CEF), PII redaction |
| Unit | compliance_collector | Report generation, deviation detection |
| Property | PII redaction | All configured fields absent in output |
| Property | ASFF FindingId | Same input → same output (deterministic) |
| Template | spoke-monitoring.yaml | Cross-account IAM validation |
| Integration | Multi-account event flow | Mock cross-account publish |
| Benchmark | Load scripts | Dry-run mode (no real infra) |

## Non-Functional Requirements

| Aspect | Target |
|--------|--------|
| Security Hub publish latency | < 10s from EventBridge event |
| SIEM delivery latency | < 60s (batching window) |
| Compliance report generation | < 5 minutes |
| Cross-account event delivery | < 5s |
| Benchmark execution (single run) | < 30 minutes |
| Article publication cadence | 1 article per 2 weeks |
