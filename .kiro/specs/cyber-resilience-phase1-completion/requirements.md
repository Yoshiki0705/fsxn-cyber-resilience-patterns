# Requirements Document

## Introduction

Phase 1 completion tasks for the FSx for ONTAP Cyber Resilience Patterns project. The project currently has CloudFormation templates, Lambda function implementations, shared modules, and CI/CD in place, but several integration gaps prevent the architecture from functioning end-to-end. This spec addresses: Lambda code packaging (replacing inline ZipFile placeholders with the full implementations), ONTAP native security automation via Custom Resource, unit tests for new handlers, observability dashboard deployment, S3 AP batch scanning integration, deployment automation improvements, and security hardening.

## Glossary

- **Event_Driven_Stack**: The CloudFormation stack (`event-driven.yaml`) containing SQS, EventBridge, Step Functions, and Lambda functions for automated security response.
- **Scanning_Stack**: The CloudFormation stack (`scanning.yaml`) deploying EC2 scanner instances for TrendAI and Deep Instinct.
- **Observability_Stack**: The CloudFormation stack (`observability.yaml`) deploying the security monitoring CloudWatch Dashboard and associated alarms.
- **Packaging_System**: The mechanism that bundles Lambda function source code from `solutions/` into deployable artifacts (S3 or inline) referenced by CloudFormation templates.
- **Security_Config_Resource**: The CloudFormation Custom Resource (Lambda-backed) that configures ONTAP ARP and FPolicy settings via the ONTAP REST API.
- **Event_Transformer_Lambda**: The Lambda function that receives FPolicy/ARP events from SQS and publishes normalized events to EventBridge.
- **Quarantine_Lambda**: The Lambda function that performs ONTAP REST API operations (restrict export policy, create snapshots, create clones) during the quarantine workflow.
- **Verdict_Handler_Lambda**: The Lambda function that processes Deep Instinct verdict events and publishes to EventBridge.
- **Scan_Result_Handler_Lambda**: The Lambda function that processes TrendAI scan verdicts and publishes to EventBridge.
- **Dashboard_Generator**: The Python module (`dashboard_config.py`) that generates CloudWatch Dashboard JSON widget definitions.
- **Metrics_Publisher**: The Python module (`security_metrics.py`) that publishes custom security metrics to CloudWatch.
- **Deploy_Orchestrator**: The deployment script (`deploy.sh`) that coordinates multi-stack CloudFormation deployments with proper ordering.
- **ONTAP_Client**: The shared Python module (`ontap_client.py`) providing the ONTAP REST API client for all Lambda functions.

## Requirements

### Requirement 1: Lambda Code Packaging

**User Story:** As a deployer, I want the event-driven.yaml CloudFormation template to reference the full Lambda implementations from `solutions/`, so that the deployed Lambda functions contain complete business logic instead of inline placeholder code.

#### Acceptance Criteria

1. WHEN the Event_Driven_Stack is deployed, THE Packaging_System SHALL bundle the Event_Transformer_Lambda source code from `solutions/event-driven-response/lambda/` into a deployable artifact referenced by the CloudFormation template.
2. WHEN the Event_Driven_Stack is deployed, THE Packaging_System SHALL bundle the Quarantine_Lambda source code from `solutions/event-driven-response/lambda/` and the ONTAP_Client from `solutions/shared/` into a deployable artifact.
3. WHEN the Event_Driven_Stack is deployed, THE Packaging_System SHALL bundle the Verdict_Handler_Lambda source code from `solutions/deep-instinct/` into a deployable artifact.
4. WHEN the Event_Driven_Stack is deployed, THE Packaging_System SHALL bundle the Scan_Result_Handler_Lambda source code from `solutions/trendai-file-security/` into a deployable artifact.
5. THE Packaging_System SHALL produce a zip archive for each Lambda function and upload it to a configured S3 bucket with a versioned key prefix.
6. THE Event_Driven_Stack SHALL reference Lambda code via `Code.S3Bucket` and `Code.S3Key` properties instead of inline `Code.ZipFile`.
7. THE Packaging_System SHALL include the `solutions/shared/` directory contents (including `ontap_client.py`) in any Lambda package that requires ONTAP REST API access.
8. THE S3 bucket used for Lambda artifacts SHALL have a bucket policy restricting `s3:GetObject` to the Lambda execution roles only.
9. THE Event_Driven_Stack SHALL configure Lambda MemorySize to 256 MB maximum and Timeout to 300 seconds maximum for cost control.

### Requirement 2: ONTAP Native Security Automation

**User Story:** As a deployer, I want ONTAP ARP and FPolicy to be automatically configured during stack creation, so that storage-native security is enabled without manual ONTAP CLI interaction.

#### Acceptance Criteria

1. WHEN the Storage Stack is created, THE Security_Config_Resource SHALL enable ARP in learning mode (dry_run state) on all specified volume UUIDs via the ONTAP REST API.
2. WHEN the Storage Stack is created with an FPolicy configuration, THE Security_Config_Resource SHALL create an FPolicy engine, event, and policy on the target SVM via the ONTAP REST API.
3. WHEN the Storage Stack is created with scanner server IPs, THE Security_Config_Resource SHALL configure the FPolicy engine with those IPs as primary servers on port 1344.
4. WHEN the Security_Config_Resource is deleted, THE Security_Config_Resource SHALL disable FPolicy policies but SHALL preserve ARP configuration on all volumes.
5. IF the ONTAP REST API returns a duplicate-resource error during FPolicy configuration, THEN THE Security_Config_Resource SHALL log the condition and continue without failing the CloudFormation operation.
6. IF the ONTAP REST API is unreachable, THEN THE Security_Config_Resource SHALL return a FAILED status to CloudFormation with a descriptive error message within 300 seconds.
7. THE Security_Config_Resource SHALL configure FPolicy with `is_mandatory: false` by default (passthrough-on-error for availability).
8. THE deployment guide SHALL document the operational procedure for transitioning ARP from dry_run to enabled state after the learning period (minimum 2 weeks recommended).
9. THE Security_Config_Resource SHALL retrieve ONTAP credentials exclusively from Secrets Manager (never from Lambda environment variables or CloudFormation parameters).

### Requirement 3: Unit Tests for Scanner Handlers

**User Story:** As a developer, I want comprehensive unit tests for verdict_handler.py, scan_result_handler.py, security_metrics.py, and dashboard_config.py, so that code quality and correctness are validated in CI.

#### Acceptance Criteria

1. THE test suite SHALL include tests for the Verdict_Handler_Lambda that verify correct EventBridge event generation for malicious, suspicious, and benign classifications.
2. THE test suite SHALL include tests for the Verdict_Handler_Lambda that verify correct severity mapping (CRITICAL for malicious with confidence >= 0.9, HIGH for malicious with confidence < 0.9, MEDIUM for suspicious with confidence >= 0.7).
3. THE test suite SHALL include tests for the Scan_Result_Handler_Lambda that verify normalization of TrendAI File Security API format, standard format, and S3 AP batch scan result format.
4. THE test suite SHALL include tests for the Scan_Result_Handler_Lambda that verify SQS-wrapped and SNS-wrapped event extraction.
5. THE test suite SHALL include tests for the Metrics_Publisher that verify correct CloudWatch put_metric_data calls with expected namespace, dimensions, and metric values.
6. THE test suite SHALL include tests for the Dashboard_Generator that verify the generated JSON contains all expected widget definitions with correct metric references.
7. FOR ALL valid verdict payloads, parsing then normalizing then mapping to detail-type SHALL produce a non-empty string from the defined mapping set (round-trip property).
8. WHEN a test for the Verdict_Handler_Lambda is executed with a randomly generated classification and confidence, THE severity mapping SHALL always return one of CRITICAL, HIGH, MEDIUM, LOW, or INFO.

### Requirement 4: Observability Dashboard Deployment

**User Story:** As an operator, I want a CloudFormation template that deploys the security monitoring CloudWatch Dashboard, so that security posture is visible without manual dashboard creation.

#### Acceptance Criteria

1. THE Observability_Stack SHALL deploy a CloudWatch Dashboard resource with widgets for SecurityEventsReceived, MalwareDetected, RansomwareAlerts, QuarantineExecuted, ScanLatencyP99, DlqMessages, and FalsePositives metrics.
2. THE Observability_Stack SHALL accept ProjectName, Environment, and Region parameters and use them to construct metric dimensions.
3. THE Observability_Stack SHALL deploy CloudWatch Alarms for malware burst detection (threshold: 10 events in 5 minutes) and ransomware alert detection (threshold: 1 event).
4. WHEN a malware burst alarm triggers, THE Observability_Stack SHALL send a notification to the security alert SNS topic.
5. THE Observability_Stack SHALL pass cfn-lint validation and cfn-guard security rules without errors.
6. THE Observability_Stack Dashboard SHALL reference metrics only within the deployment region (no cross-region metric references).

### Requirement 5: S3 AP Batch Scanning Integration

**User Story:** As a security operator, I want TrendAI batch scanning via FSx for ONTAP S3 AP to forward results into the event-driven pipeline, so that batch-scanned files receive the same quarantine response as real-time detections.

#### Acceptance Criteria

1. WHEN an S3 AP batch scan result is received by the Scan_Result_Handler_Lambda, THE Scan_Result_Handler_Lambda SHALL normalize the result into the standard security event format with scan_type set to "batch".
2. WHEN a batch scan result has status "MALICIOUS", THE Scan_Result_Handler_Lambda SHALL publish an event with detail-type "MalwareDetected" to EventBridge.
3. THE Event_Driven_Stack SHALL include an SQS queue or SNS subscription that receives S3 AP batch scan completion notifications and routes them to the Scan_Result_Handler_Lambda.
4. THE Scan_Result_Handler_Lambda SHALL handle both real-time Vscan/ICAP verdicts and S3 AP batch scan results through a unified handler entry point.

### Requirement 6: Deployment Automation

**User Story:** As a deployer, I want the deployment script to orchestrate all stacks (network, storage, event-driven, scanning, observability) in the correct dependency order, so that a single command deploys the full architecture.

#### Acceptance Criteria

1. THE Deploy_Orchestrator SHALL deploy stacks in the order: network → storage → event-driven → scanning → observability.
2. THE Deploy_Orchestrator SHALL use `aws cloudformation wait stack-create-complete` (or `stack-update-complete`) to block until each stack reaches a terminal state before deploying dependent stacks.
3. THE Deploy_Orchestrator SHALL support deploying individual stacks by name (network, storage, events, scanning, observability) or all stacks together.
4. WHEN deploying with Lambda code packaging, THE Deploy_Orchestrator SHALL execute the packaging step (zip + S3 upload) before deploying the event-driven stack.
5. IF a stack deployment fails, THEN THE Deploy_Orchestrator SHALL halt subsequent deployments and report the failure with the stack name and error reason.
6. THE Deploy_Orchestrator SHALL support both new-VPC deployment and existing-VPC (bring-your-own) deployment modes.
7. WHEN deploying to the production environment, THE Deploy_Orchestrator SHALL require explicit confirmation before proceeding.

### Requirement 7: Security Hardening

**User Story:** As a security auditor, I want EC2 instances to enforce IMDSv2, VPC Flow Logs to be enabled, and CloudTrail integration to be configured, so that the deployment meets AWS security best practices.

#### Acceptance Criteria

1. THE Scanning_Stack SHALL configure EC2 instances with a Launch Template that enforces IMDSv2 (HttpTokens: required, HttpPutResponseHopLimit: 1).
2. THE network stack or a dedicated security stack SHALL enable VPC Flow Logs to a CloudWatch Logs log group with a retention period of at least 90 days.
3. THE Scanning_Stack SHALL tag all EC2 instances with metadata sufficient for CloudTrail correlation (Project, Environment, Layer, Component).
4. THE Scanning_Stack SHALL configure EBS volumes with encryption enabled using either a customer-managed KMS key or the default aws/ebs key.
5. THE Event_Driven_Stack SHALL configure all Lambda functions with reserved concurrent execution limits to prevent runaway invocations.

### Requirement 8: End-to-End Event Flow Testing

**User Story:** As a developer, I want integration test definitions that validate the complete event flow from FPolicy event ingestion through to quarantine execution, so that the pipeline correctness is verifiable.

#### Acceptance Criteria

1. THE test suite SHALL include an integration test specification that defines the expected data transformations at each stage: raw FPolicy event → SQS message → Event_Transformer_Lambda → EventBridge event → Step Functions execution.
2. THE test suite SHALL include a mock-based integration test that verifies the Event_Transformer_Lambda correctly publishes events that match the EventBridge rule patterns for quarantine routing.
3. THE test suite SHALL include tests verifying that the quarantine workflow Step Functions state machine definition correctly references the Quarantine_Lambda ARN and SNS topic ARN.
4. FOR ALL valid raw FPolicy events with source in {fpolicy, arp, scanner}, transforming then classifying the detail-type SHALL produce one of the defined EventBridge detail-types (MalwareDetected, RansomwareDetected, SuspiciousActivity, FileEvent).

### Requirement 9: Documentation Updates

**User Story:** As a user of this reference architecture, I want the deployment runbook and architecture diagrams to reflect the current state including all Phase 1 components, so that I can understand and deploy the complete system.

#### Acceptance Criteria

1. THE deployment guide SHALL document the Lambda packaging step and S3 bucket prerequisites.
2. THE deployment guide SHALL document the correct stack deployment order with cross-stack dependency explanations.
3. THE architecture overview document SHALL include the observability layer (CloudWatch Dashboard, custom metrics, alarms) in the architecture diagram description.
4. THE deployment guide SHALL document the ONTAP native security automation (Custom Resource) including required IAM permissions and Secrets Manager prerequisites.
5. THE ransomware recovery runbook SHALL reference the automated quarantine workflow and explain how to approve or reject quarantine decisions via the approval queue.
6. ALL documentation updates SHALL maintain bilingual parity (Japanese primary + English) with matching section structure.

### Requirement 10: CI Pipeline Enhancement

**User Story:** As a developer, I want the CI pipeline to validate Lambda packaging, run the new unit tests, and report coverage for all solution modules, so that regressions are caught before merge.

#### Acceptance Criteria

1. THE CI pipeline SHALL execute pytest against all test directories including new scanner handler tests, observability tests, and integration test specifications.
2. THE CI pipeline SHALL report code coverage for `solutions/` with a minimum threshold of 80%.
3. THE CI pipeline SHALL validate that Lambda packaging produces valid zip archives before template deployment.
4. WHEN a pull request modifies files in `solutions/` or `tests/`, THE CI pipeline SHALL run the full test suite including property-based tests.
5. THE CI pipeline total execution time SHALL remain under 5 minutes for the lint-and-test job.
