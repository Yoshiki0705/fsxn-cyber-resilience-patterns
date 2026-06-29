# Requirements Document

## Introduction

Phase 2 は Phase 1 で構築した基盤を本番運用可能なレベルに引き上げる。高可用性 (Multi-AZ スキャナー、Auto Scaling)、ARP 学習完了後の本番移行自動化、DR/SnapMirror 連携、Multi-Admin Verification (MAV) による人間承認フロー、コスト制御 (dev 環境の時間帯停止) を対象とする。

## Glossary

- **Scanner_ASG**: Auto Scaling Group for Vscan/Deep Instinct EC2 instances across multiple AZs.
- **ARP_Lifecycle_Manager**: Lambda function that manages ARP state transitions (dry_run → enabled) based on learning period duration.
- **DR_Replication_Stack**: CloudFormation stack for cross-region SnapMirror and backup orchestration.
- **MAV_Integration**: Multi-Admin Verification workflow that requires multiple administrator approvals before destructive ONTAP operations.
- **Cost_Scheduler**: EventBridge Scheduler that stops/starts scanner EC2 instances based on time-of-day schedules.
- **Health_Check_Lambda**: Lambda function that validates scanner health via ICAP connectivity test.

## Requirements

### Requirement 1: Multi-AZ Scanner High Availability

**User Story:** As an operator, I want scanner instances deployed across multiple AZs with automatic recovery, so that a single AZ failure does not disrupt file scanning.

#### Acceptance Criteria

1. THE Scanning_Stack SHALL deploy scanner instances in both SubnetSecurity1 and SubnetSecurity2 (Multi-AZ).
2. THE Scanning_Stack SHALL use an Auto Scaling Group with min=1, desired=2, max=4 for each enabled scanner type.
3. THE Scanner_ASG SHALL distribute instances across 2 AZs using a mixed instances policy.
4. WHEN an instance fails its health check, THE Scanner_ASG SHALL terminate and replace it within 5 minutes.
5. THE Scanner_ASG health check SHALL use a custom Lambda-based health check (ICAP port 1344 connectivity), not ELB health checks.
6. THE FPolicy engine configuration SHALL include both AZ instances as primary and secondary servers for failover.
7. THE Health_Check_Lambda SHALL verify ICAP connectivity (TCP 1344) to each scanner instance every 60 seconds and publish results to CloudWatch.

### Requirement 2: ARP Lifecycle Management

**User Story:** As a storage administrator, I want ARP to automatically transition from learning mode to active protection after the configured learning period, so that ransomware detection is enforced without manual intervention.

#### Acceptance Criteria

1. THE ARP_Lifecycle_Manager SHALL track the ARP learning start time per volume in a DynamoDB table.
2. WHEN the configured learning period (default: 30 days) has elapsed, THE ARP_Lifecycle_Manager SHALL transition the volume's ARP state from dry_run to enabled via the ONTAP REST API.
3. BEFORE transitioning ARP to enabled state, THE ARP_Lifecycle_Manager SHALL publish a notification to the security alert SNS topic requesting administrator acknowledgment.
4. THE ARP_Lifecycle_Manager SHALL be triggered by an EventBridge Scheduler rule on a daily cadence.
5. IF the ONTAP REST API call to enable ARP fails, THE ARP_Lifecycle_Manager SHALL retry 3 times and then alert via SNS with the error details.
6. THE deployment guide SHALL document the learning period configuration parameter and the expected ARP state transition timeline.

### Requirement 3: DR and Cross-Region Replication

**User Story:** As a disaster recovery planner, I want automated SnapMirror configuration and cross-region backup validation, so that ransomware recovery can be performed from an isolated copy.

#### Acceptance Criteria

1. THE DR_Replication_Stack SHALL configure SnapMirror relationships between primary and DR region FSx for ONTAP file systems via the ONTAP REST API.
2. THE DR_Replication_Stack SHALL schedule SnapMirror updates at a configurable interval (default: 15 minutes RPO).
3. THE DR_Replication_Stack SHALL configure SnapMirror with in-flight encryption (cluster peering TLS) between primary and DR FSx for ONTAP file systems.
4. THE DR_Replication_Stack SHALL include a Lambda function that validates SnapMirror lag time and alerts when lag exceeds 2x the configured interval.
5. THE ransomware recovery runbook SHALL document the SnapMirror break and failover procedure.
6. THE DR_Replication_Stack SHALL NOT deploy to the same region as the primary stack (enforced by parameter validation).

### Requirement 4: Multi-Admin Verification (MAV) Integration

**User Story:** As a security officer, I want destructive ONTAP operations (volume delete, ARP disable, export policy change) to require approval from multiple administrators, so that insider threats and accidental changes are mitigated.

#### Acceptance Criteria

1. THE MAV_Integration SHALL configure MAV on the FSx for ONTAP file system via the ONTAP REST API Custom Resource.
2. THE MAV_Integration SHALL define protected operations: volume delete, volume offline, export policy modify, ARP disable, snapshot policy delete.
3. WHEN a MAV-protected operation is requested, THE MAV_Integration SHALL route the approval request to the existing Step Functions approval queue.
4. THE MAV_Integration SHALL require a minimum of 2 administrator approvals before the operation proceeds.
5. THE MAV_Integration SHALL enforce a maximum approval window of 24 hours, after which the request is automatically denied.
6. THE deployment guide SHALL document the MAV configuration including required ONTAP admin roles.
7. ALL MAV approval and denial events SHALL be logged to CloudTrail for audit compliance.

### Requirement 5: Cost Optimization — Scheduled Scanner Control

**User Story:** As a cost-conscious operator, I want scanner instances in dev/staging environments to stop during non-business hours, so that compute costs are minimized without manual intervention.

#### Acceptance Criteria

1. THE Cost_Scheduler SHALL stop scanner EC2 instances at a configurable time (default: 20:00 JST) in non-production environments.
2. THE Cost_Scheduler SHALL start scanner EC2 instances at a configurable time (default: 08:00 JST) in non-production environments.
3. THE Cost_Scheduler SHALL NOT apply to production environment instances (enforced by condition).
4. WHEN instances are stopped, THE FPolicy configuration SHALL remain in passthrough mode (is_mandatory: false ensures no I/O blocking).
5. THE Cost_Scheduler SHALL use EventBridge Scheduler with IAM role scoped to ec2:StopInstances/ec2:StartInstances on tagged instances only.
6. THE CloudWatch Alarms for scanner health SHALL use TreatMissingData: notBreaching to prevent false alerts during scheduled downtime.

### Requirement 6: Operational Runbooks

**User Story:** As an on-call engineer, I want step-by-step operational runbooks for common Day-2 operations, so that incidents can be resolved quickly with minimal escalation.

#### Acceptance Criteria

1. THE runbook collection SHALL include procedures for: ARP alert triage, false positive resolution, scanner failover, SnapMirror failover, MAV approval, quarantine un-quarantine.
2. EACH runbook SHALL include: trigger condition, severity classification, step-by-step procedure, rollback steps, and escalation path.
3. THE runbooks SHALL be bilingual (Japanese primary + English).
4. THE runbooks SHALL reference specific AWS CLI commands, ONTAP REST API calls, and console navigation paths.
5. THE runbooks SHALL be linked from the CloudWatch Dashboard via annotation URLs.
