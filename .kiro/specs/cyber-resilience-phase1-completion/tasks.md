# Implementation Plan: Phase 1 Completion

## Overview

11 tasks to bring the FSx for ONTAP Cyber Resilience Patterns project to Phase 1 completion. Tasks are ordered by dependency and implementation priority.

## Task Dependency Graph

```json
{
  "waves": [
    {"wave": 1, "tasks": [1, 3, 4, 5, 6], "description": "Independent implementation tracks (parallel)"},
    {"wave": 2, "tasks": [2, 7], "description": "Depends on packaging (1) and event-driven structure"},
    {"wave": 3, "tasks": [8, 9], "description": "Integration: deploy orchestration and E2E tests"},
    {"wave": 4, "tasks": [10, 11], "description": "Documentation and CI finalization"}
  ]
}
```

## Tasks

- [ ] 1. Create `scripts/package-lambdas.sh` — Lambda zip packaging with content-hash S3 upload, shared/ inclusion, idempotent skip. Add `lambda-packages/` to `.gitignore`. Document S3 bucket prerequisites (SSE, bucket policy). #req-1
- [ ] 2. Update `templates/event-driven.yaml` — Replace `Code.ZipFile` with `S3Bucket`/`S3Key` for all 4 Lambdas. Add `LambdaArtifactBucket`/`LambdaArtifactPrefix` parameters. Add `ReservedConcurrentExecutions` (Quarantine: 10, EventTransformer: 50). Verify cfn-lint, run `make test`. #req-1 #req-7
- [ ] 3. Enhance ONTAP Security Config Custom Resource — Update `security_config_handler.py` for Create/Update/Delete lifecycle. Implement ARP dry_run, FPolicy engine/event/policy creation (idempotent, handle 409). Add timeout guard. Update `storage.yaml`. Create `tests/test_security_config_handler.py`. #req-2
- [ ] 4. Write unit tests for scanner handlers — Create `tests/test_verdict_handler.py`, `tests/test_scan_result_handler.py`, `tests/test_security_metrics.py`, `tests/test_dashboard_config.py`. Add property-based tests for `_map_severity` and `_normalize_verdict` (50 runs). Add `mock_env_vars` fixture to `conftest.py`. #req-3
- [ ] 5. Create `templates/observability.yaml` — CloudWatch Dashboard (7 metrics), MalwareBurstAlarm (≥10/5min), RansomwareAlarm (≥1), ScanLatencyAlarm (p99>100ms). Accept SecurityAlertTopicArn parameter. Same-region metrics only. Verify cfn-lint + cfn-guard. Add template tests. #req-4
- [ ] 6. Security hardening — Add Launch Templates to `scanning.yaml` (IMDSv2: HttpTokens required). Add VPC Flow Logs to `network.yaml` (Condition: CreateNewVpc, 90-day retention). Add FlowLogRole IAM. Verify cfn-lint. #req-7
- [ ] 7. Add S3 AP batch scanning queue — Add `BatchScanResultQueue` + DLQ to `event-driven.yaml` (WaitTimeSeconds: 20, KMS encrypted). Add Lambda event source mapping for Scan_Result_Handler. Add SNS subscription policy. Update Lambda role permissions. #req-5
- [ ] 8. Enhance `scripts/deploy.sh` — Add `package`, `scanning`, `observability` subcommands. Implement `all` flow with `aws cloudformation wait`. Integrate `package-lambdas.sh` before events stack. Add `--existing-vpc` flag. Report failures with stack name. #req-6
- [ ] 9. Create end-to-end event flow tests — `tests/test_event_flow_integration.py` with mock-based pipeline validation. Test FPolicy→SQS→EventTransformer→EventBridge pattern matching. Validate Step Functions ASL references. Property test for event classification. #req-8
- [ ] 10. Update documentation — Deployment guide: packaging prereqs, stack order, Custom Resource docs. Architecture overview: observability layer. Runbook: quarantine approval procedure. README: Project Structure update. JA/EN bilingual parity. #req-9
- [ ] 11. CI pipeline enhancement — Add `--cov=solutions --cov-fail-under=80` to pytest. Add Lambda zip validation step. Verify CI < 5 minutes. #req-10

## Notes

- Tasks 1-2, 3, 4, 5, 6 can be parallelized (independent tracks)
- Task 8 integrates outputs from Tasks 1, 2, 5
- Task 9 requires Tasks 2, 4 completed first
- Task 10 is a documentation sweep after all implementation
- Task 11 is a CI config update, best done after Task 4
- Property-based tests use `numRuns: 50` (Lambda logic is lightweight)
- All tests are mock-based (no real AWS calls in CI)
- Integration tests (e2e-*) are excluded from CI scope for this phase
