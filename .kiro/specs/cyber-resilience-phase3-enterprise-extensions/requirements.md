# Requirements Document

## Introduction

Phase 3 はエンタープライズ規模の拡張機能を追加する。SIEM 連携 (AWS Security Hub / 3rd-party)、コンプライアンス証跡収集、AWS Organizations マルチアカウント展開パターン、パフォーマンスベンチマーク、および公開技術記事 (dev.to) の作成を対象とする。fsxn-observability-integrations プロジェクトとの統合もこのフェーズで完成させる。

## Glossary

- **SIEM_Connector**: Lambda function that transforms security events into SIEM-specific formats (Security Hub ASFF, Splunk HEC, QRadar LEEF).
- **Compliance_Collector**: Lambda function that generates periodic compliance evidence reports from ONTAP state (ARP status, SnapLock retention, FPolicy health).
- **Multi_Account_Pattern**: CloudFormation StackSets or Organizations-level deployment pattern for hub-and-spoke security monitoring.
- **Benchmark_Suite**: Performance test framework measuring scan latency, quarantine response time, and event pipeline throughput under load.
- **Article_Series**: dev.to technical article series documenting the architecture, implementation, and operational patterns.
- **Security_Hub_Integration**: AWS Security Hub findings publisher that maps EventBridge security events to ASFF format.

## Requirements

### Requirement 1: AWS Security Hub Integration

**User Story:** As a security operations team, I want all security events to appear as findings in AWS Security Hub, so that we have a unified security posture view across all AWS services.

#### Acceptance Criteria

1. THE SIEM_Connector SHALL transform EventBridge security events into AWS Security Finding Format (ASFF) and publish to Security Hub via BatchImportFindings API.
2. THE SIEM_Connector SHALL map severity levels (CRITICAL, HIGH, MEDIUM, LOW, INFO) to Security Hub severity labels.
3. THE SIEM_Connector SHALL include resource identifiers (FSx file system ID, volume ID, SVM ID) in the ASFF Resources array.
4. THE SIEM_Connector SHALL set Finding ProductArn using the custom integration registration ARN.
5. THE SIEM_Connector SHALL update existing findings (via FindingId) when the same file triggers multiple detection events.
6. THE deployment SHALL register a custom Security Hub product integration during stack creation.

### Requirement 2: Third-Party SIEM Connector

**User Story:** As an enterprise with an existing SIEM investment, I want security events forwarded to Splunk or QRadar, so that file security events are correlated with other enterprise security data.

#### Acceptance Criteria

1. THE SIEM_Connector SHALL support configurable output formats: Splunk HEC (JSON), QRadar LEEF, and generic CEF.
2. THE SIEM_Connector SHALL forward events via HTTPS to a configurable endpoint URL.
3. THE SIEM_Connector SHALL authenticate to the SIEM endpoint using credentials stored in Secrets Manager.
4. THE SIEM_Connector SHALL batch events (configurable: 10-100 events or 5-60 seconds) for efficient delivery.
5. IF delivery to the SIEM endpoint fails, THEN THE SIEM_Connector SHALL retry with exponential backoff and fall back to S3 dead-letter storage after 3 failures.
6. THE SIEM_Connector SHALL be deployed as an optional component (enabled/disabled via stack parameter).
7. THE SIEM_Connector SHALL redact PII fields (clientIp, userName) based on a configurable redaction policy before forwarding to external SIEM endpoints.

### Requirement 3: Compliance Evidence Collection

**User Story:** As a compliance officer, I want automated periodic reports on security control status (ARP, FPolicy, SnapLock, encryption), so that audit evidence is generated without manual data collection.

#### Acceptance Criteria

1. THE Compliance_Collector SHALL query ONTAP REST API daily for: ARP status per volume, FPolicy status per SVM, SnapLock retention per volume, encryption status.
2. THE Compliance_Collector SHALL produce a JSON report stored in S3 with a date-partitioned key structure.
3. THE Compliance_Collector SHALL compare current state against expected baseline and flag deviations as non-compliant.
4. WHEN a non-compliance deviation is detected, THE Compliance_Collector SHALL publish a CRITICAL alert to the security alert SNS topic.
5. THE compliance reports SHALL be stored in a SnapLock-protected S3 bucket (via Object Lock) with a minimum retention of 365 days.
6. THE compliance report format SHALL include: timestamp, control_id, expected_state, actual_state, compliant (boolean), evidence_detail.
7. THE compliance report control_ids SHALL map to SOC2 CC6.1/CC6.6/CC6.7 and ISO27001 A.8.1/A.12.3/A.12.4 control categories where applicable.

### Requirement 4: Multi-Account Deployment Pattern

**User Story:** As an enterprise architect, I want a hub-and-spoke deployment pattern where a central security account aggregates events from multiple workload accounts with FSx for ONTAP, so that security monitoring scales across the organization.

#### Acceptance Criteria

1. THE Multi_Account_Pattern SHALL define a hub account (security monitoring) and spoke accounts (workload accounts with FSx for ONTAP).
2. THE Multi_Account_Pattern SHALL use EventBridge cross-account event bus rules to forward security events from spoke to hub.
3. THE Multi_Account_Pattern SHALL provide a CloudFormation StackSet template for deploying spoke-side resources across an AWS Organization.
4. THE hub account SHALL aggregate Security Hub findings from all spoke accounts via Security Hub organization integration.
5. THE Multi_Account_Pattern SHALL enforce least-privilege cross-account IAM roles (spoke → hub event publishing only).
6. THE deployment guide SHALL document the Organizations setup prerequisites and account structure.

### Requirement 5: Performance Benchmark Suite

**User Story:** As a solutions architect, I want reproducible performance benchmarks measuring scan latency, event pipeline throughput, and quarantine response time, so that capacity planning guidance is evidence-based.

#### Acceptance Criteria

1. THE Benchmark_Suite SHALL measure end-to-end scan latency (file write → ICAP → verdict → EventBridge) under configurable load (100, 500, 1000 files/minute).
2. THE Benchmark_Suite SHALL measure quarantine response time (EventBridge event → export policy restricted) under isolation.
3. THE Benchmark_Suite SHALL measure event pipeline throughput (max events/second before DLQ overflow).
4. THE Benchmark_Suite SHALL produce results in a structured JSON format with percentile distributions (p50, p95, p99).
5. THE Benchmark_Suite SHALL include environment metadata (instance types, FSx throughput capacity, IOPS) for reproducibility.
6. ALL benchmark results published in documentation SHALL include explicit caveats: test environment specification, not production estimates, and "results may vary" disclaimer.
7. THE Benchmark_Suite documentation SHALL include estimated execution cost per benchmark run (compute + FSx I/O + Lambda invocations).

### Requirement 6: Technical Article Series

**User Story:** As an AWS Community Builder, I want a series of dev.to articles documenting this reference architecture, so that the community benefits from the patterns and the project gains visibility.

#### Acceptance Criteria

1. THE Article_Series SHALL consist of at least 4 articles: architecture overview, ONTAP native security deep-dive, event-driven response implementation, and operational lessons learned.
2. EACH article SHALL be written in English with a Japanese summary section at the end.
3. THE articles SHALL reference the GitHub repository with deployment instructions.
4. THE articles SHALL include architecture diagrams (Mermaid or image) and code snippets from the repository.
5. THE articles SHALL follow vendor-neutrality principles: symmetric trade-off descriptions, no "beats competitor" framing.
6. THE articles SHALL be reviewed by at least 2 role-based perspectives (Storage Specialist + DevOps/SRE) before publication.
