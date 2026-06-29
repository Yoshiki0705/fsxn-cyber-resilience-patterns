# Implementation Plan: Phase 3 — Enterprise Extensions

## Overview

10 tasks to extend the architecture for enterprise-scale operations: SIEM integration, compliance automation, multi-account patterns, performance benchmarking, and community publication.

## Task Dependency Graph

```json
{
  "waves": [
    {"wave": 1, "tasks": [1, 2, 3, 5], "description": "Independent SIEM, compliance, and benchmark development"},
    {"wave": 2, "tasks": [4, 6], "description": "Multi-account (needs SIEM), benchmark execution (needs Phase 2 HA)"},
    {"wave": 3, "tasks": [7, 8], "description": "Integration testing and documentation"},
    {"wave": 4, "tasks": [9, 10], "description": "Article series and final review"}
  ]
}
```

## Tasks

- [ ] 1. Create Security Hub integration — `solutions/siem/security_hub_publisher.py`: EventBridge→Lambda→BatchImportFindings. ASFF mapping, FindingId deduplication, product registration Custom Resource. Add EventBridge rule in `event-driven.yaml`. Create `tests/test_security_hub_publisher.py` with ASFF format validation. #req-1
- [ ] 2. Create third-party SIEM forwarder — `solutions/siem/siem_forwarder.py`: Splunk HEC, QRadar LEEF, CEF format conversion. PII redaction module. SQS batching (30s window, batch 50). S3 dead-letter for failures. Secrets Manager auth. Create `tests/test_siem_forwarder.py` with property test for PII redaction completeness. #req-2
- [ ] 3. Create compliance evidence collector — `solutions/compliance/compliance_collector.py`: Daily ONTAP API queries, JSON report generation, S3 Object Lock storage. SOC2/ISO27001 control mapping. Deviation detection → SNS alert. Create `tests/test_compliance_collector.py`. #req-3
- [ ] 4. Create multi-account hub-spoke pattern — `templates/spoke-monitoring.yaml` (StackSet-deployable): cross-account EventBridge rule, IAM role (events:PutEvents only). Hub-side bus policy. StackSet deployment instructions. Create `templates/hub-aggregation.yaml` for hub account. #req-4
- [ ] 5. Create benchmark suite — `benchmarks/run_benchmark.py`, `load_generator.py`, `latency_collector.py`. Measure scan latency, pipeline throughput, quarantine response. JSON results with cost estimation. README with methodology and caveats. #req-5
- [ ] 6. Execute benchmarks and publish results — Run benchmark suite against test environment. Generate p50/p95/p99 latency distributions. Document results with environment metadata and caveats. Add `docs/benchmarks/scan-latency.md` and `docs/benchmarks/pipeline-throughput.md`. #req-5
- [ ] 7. Integration tests for Phase 3 — Security Hub ASFF validation, SIEM format conversion round-trip, compliance report determinism, cross-account IAM policy simulation. All mock-based (no real AWS). #req-1 #req-2 #req-3 #req-4
- [ ] 8. Create `templates/siem-integration.yaml` — Optional stack: Security Hub product registration, SIEM forwarder Lambda + SQS, compliance collector Lambda + DynamoDB + S3. Conditional deployment (enabled/disabled per connector). cfn-lint + cfn-guard validation. #req-1 #req-2 #req-3
- [ ] 9. Write dev.to article series — Article 1: Architecture overview. Article 2: ONTAP native security deep-dive. Article 3: Event-driven response implementation. Article 4: Operational patterns and benchmarks. Role-based review (Storage Specialist + DevOps/SRE) before each publication. JA summary section in each article. #req-6
- [ ] 10. Final documentation and README update — Update README with Phase 3 components. Update architecture overview diagram. Update deployment guide with SIEM/compliance/multi-account sections. Verify README ↔ article consistency. Naming standardization audit. JA/EN parity. #req-6

## Notes

- Phase 3 depends on Phase 1 + Phase 2 completion
- Security Hub integration requires `securityhub:BatchImportFindings` permission and product registration
- Multi-account pattern requires AWS Organizations setup (use existing test account infrastructure)
- Benchmark suite requires a deployed environment (Phase 2 HA scanners) — dry-run mode for CI
- Article series follows the 2-week cadence; first article can start after Phase 2 Task 7 (runbooks)
- SIEM forwarder is optional — deployed via parameter flag, not by default
- Compliance reports use S3 Object Lock (requires bucket with Object Lock enabled at creation)
- PII redaction is configurable per deployment — default: enabled for external SIEM, disabled for Security Hub (within same account)
