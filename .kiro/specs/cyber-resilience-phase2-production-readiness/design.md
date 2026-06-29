# Design Document: Phase 2 — Production Readiness

## Overview

Phase 2 は Multi-AZ HA、ARP ライフサイクル管理、DR レプリケーション、MAV 統合、コストスケジューラーを追加し、本番環境で運用可能なレベルにする。

## Architecture

```
┌───────────────────────────────────────────────────────────────────────┐
│                    Production Architecture                             │
│                                                                       │
│  ┌──────────────────────────────────────────────────────────┐         │
│  │  Scanner HA (Auto Scaling Group)                         │         │
│  │  AZ-1: Vscan-1, DI-1  │  AZ-2: Vscan-2, DI-2          │         │
│  │  Health Check Lambda (60s interval)                      │         │
│  └──────────────────────────────────────────────────────────┘         │
│                                                                       │
│  ┌──────────────────┐  ┌──────────────────┐  ┌────────────────────┐  │
│  │ ARP Lifecycle    │  │ Cost Scheduler   │  │ MAV Integration    │  │
│  │ Manager (daily)  │  │ (EventBridge)    │  │ (approval queue)   │  │
│  │ DynamoDB state   │  │ Stop/Start EC2   │  │ 2-admin approval   │  │
│  └──────────────────┘  └──────────────────┘  └────────────────────┘  │
│                                                                       │
│  ┌──────────────────────────────────────────────────────────┐         │
│  │  DR Replication (Cross-Region)                           │         │
│  │  Primary (ap-northeast-1) ──SnapMirror──▶ DR (us-west-2) │         │
│  │  Lag Monitor Lambda (5-min check)                        │         │
│  └──────────────────────────────────────────────────────────┘         │
└───────────────────────────────────────────────────────────────────────┘
```

## Components and Interfaces

### 1. Scanner ASG (scanning-ha.yaml)

**Design**: Replace single EC2 Instance with ASG + Launch Template. FPolicy engine references both AZ IPs (primary + secondary failover).

**Interface**:
- Input: AMI ID, Instance Type, Security Group, Subnet list (2 AZs)
- Output: ASG logical name, instance IPs (via Lambda custom resource lookup)
- Health Check: Custom Lambda → CloudWatch metric → ASG lifecycle hook

### 2. ARP Lifecycle Manager

**Design**: DynamoDB table tracks `{volume_uuid, arp_start_date, current_state}`. Daily EventBridge Scheduler triggers Lambda. After learning period → ONTAP API call → SNS notification.

**Interface**:
```json
{
  "DynamoDB Table": "fsxn-cyber-resilience-arp-state-{env}",
  "Partition Key": "volume_uuid (S)",
  "Attributes": ["arp_start_date (S)", "current_state (S)", "learning_days (N)"]
}
```

### 3. DR Replication Stack

**Design**: Separate template (`templates/dr-replication.yaml`) deployed in DR region. Uses ONTAP REST API to establish SnapMirror relationships. Lag monitor Lambda checks every 5 minutes.

**Encryption**: Cluster peering with TLS encryption (configured via ONTAP REST API).

### 4. MAV Integration

**Design**: Extend existing Security Config Custom Resource to configure MAV rules. Approval routing reuses Step Functions approval queue pattern from Phase 1.

**Protected Operations**: volume-delete, volume-offline, export-policy-modify, arp-disable, snapshot-policy-delete.

### 5. Cost Scheduler

**Design**: EventBridge Scheduler with 2 rules per environment (stop + start). IAM role scoped to `ec2:StopInstances`/`ec2:StartInstances` with resource tag condition.

**Condition**: Only deploys when `Environment != production`.

## Correctness Properties

### Property 1: Scanner HA Failover
When one AZ's scanner becomes unavailable, FPolicy SHALL route to the secondary server within 30 seconds (ONTAP native failover behavior).
**Validates: Requirements 1.5**

### Property 2: ARP State Machine
ARP state transitions are monotonic: dry_run → enabled. No automated path exists from enabled → dry_run (requires manual override).
**Validates: Requirements 2.2**

### Property 3: MAV Quorum
A MAV-protected operation proceeds only when approval_count >= 2 AND within the 24-hour window.
**Validates: Requirements 4.4**

### Property 4: Cost Scheduler Safety
Cost Scheduler NEVER executes on instances tagged `Environment: production`.
**Validates: Requirements 5.3**

## Data Models

### ARP State Table (DynamoDB)
```json
{
  "volume_uuid": "string (PK)",
  "arp_start_date": "ISO8601 date",
  "current_state": "dry_run | enabled",
  "learning_days": 30,
  "last_check_date": "ISO8601 date",
  "transition_requested": false
}
```

### SnapMirror Relationship Config
```json
{
  "source_svm": "svm-prod",
  "source_volume": "vol-prod-data",
  "destination_endpoint": "management.fs-dr.fsx.us-west-2.amazonaws.com",
  "destination_svm": "svm-dr",
  "schedule": "15min",
  "encryption": "tls"
}
```

## Error Handling

| Component | Error | Behavior |
|-----------|-------|----------|
| Scanner ASG | Instance unhealthy | Terminate + replace (5 min) |
| ARP Lifecycle | ONTAP API failure | Retry 3x → SNS alert |
| DR Lag Monitor | Lag > 2x interval | SNS CRITICAL alert |
| MAV Approval | Timeout (24h) | Auto-deny + SNS notification |
| Cost Scheduler | Stop/Start failure | CloudWatch alarm + retry |

## Testing Strategy

| Test Type | Target | Notes |
|-----------|--------|-------|
| Unit | ARP Lifecycle Manager | State transitions, DynamoDB mocking |
| Unit | Health Check Lambda | TCP mock, CloudWatch publish |
| Unit | DR Lag Monitor | SnapMirror status parsing |
| Template | scanning-ha.yaml | ASG configuration validation |
| Template | dr-replication.yaml | Cross-region parameter validation |
| Integration | MAV flow | Step Functions ASL validation |

## Non-Functional Requirements

| Aspect | Target |
|--------|--------|
| Scanner failover time | < 30s (ONTAP FPolicy native) |
| ARP transition notification | Same-day as learning completion |
| SnapMirror RPO | ≤ 15 minutes |
| MAV approval window | 24 hours max |
| Cost savings (dev) | ~60% compute reduction (16h/day stopped) |
