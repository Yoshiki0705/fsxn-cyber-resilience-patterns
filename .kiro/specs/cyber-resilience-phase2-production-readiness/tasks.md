# Implementation Plan: Phase 2 — Production Readiness

## Overview

8 tasks to achieve production-grade operations: HA scanners, ARP automation, DR replication, MAV integration, cost scheduling, and operational runbooks.

## Task Dependency Graph

```json
{
  "waves": [
    {"wave": 1, "tasks": [1, 2, 4, 5], "description": "Independent components (ASG, ARP, MAV, Cost Scheduler)"},
    {"wave": 2, "tasks": [3, 6], "description": "DR replication (needs Phase 1 storage stack), Health checks (needs ASG)"},
    {"wave": 3, "tasks": [7, 8], "description": "Runbooks and integration testing"}
  ]
}
```

## Tasks

- [ ] 1. Create `templates/scanning-ha.yaml` — Replace single EC2 with ASG (min=1, desired=2, max=4) across 2 AZs. Use Launch Template with IMDSv2. Configure mixed instances policy. Export instance IPs for FPolicy configuration. #req-1
- [ ] 2. Create ARP Lifecycle Manager — DynamoDB state table, Lambda function (daily EventBridge trigger), ARP dry_run→enabled transition logic, SNS notification before transition, retry on API failure. Create `solutions/ontap-native/lambda/arp_lifecycle.py` + tests. #req-2
- [ ] 3. Create `templates/dr-replication.yaml` — SnapMirror relationship configuration via Custom Resource, lag monitor Lambda (5-min schedule), encrypted cluster peering, cross-region parameter validation. #req-3
- [ ] 4. Implement MAV integration — Extend Security Config Custom Resource to configure MAV protected operations. Reuse Step Functions approval queue for 2-admin approval. Add CloudTrail logging for MAV events. #req-4
- [ ] 5. Create Cost Scheduler — EventBridge Scheduler rules (stop 20:00 JST, start 08:00 JST). Scoped IAM role (tag-based ec2:StopInstances/StartInstances). Condition: non-production only. #req-5
- [ ] 6. Create Health Check Lambda — TCP 1344 ICAP connectivity test per instance. CloudWatch custom metric (ScannerHealthy: 0/1). ASG lifecycle hook integration for instance replacement. #req-1
- [ ] 7. Write operational runbooks — ARP alert triage, false positive resolution, scanner failover, SnapMirror failover, MAV approval, quarantine un-quarantine. Bilingual JA/EN. Link from CloudWatch Dashboard. #req-6
- [ ] 8. Integration tests for Phase 2 — ASG scaling policy validation, ARP state machine tests, DR lag monitor tests, MAV quorum logic tests, Cost Scheduler condition tests. #req-1 #req-2 #req-3 #req-4 #req-5

## Notes

- Phase 2 depends on Phase 1 completion (especially Tasks P1-2, P1-3, P1-5, P1-6)
- Scanner HA (Task 1) replaces `scanning.yaml` single-instance design — backward-incompatible change
- DR stack deploys in a DIFFERENT region from primary — requires cross-region credentials
- MAV requires ONTAP 9.11.1+ on the FSx for ONTAP file system
- Cost Scheduler savings estimate: c6g.xlarge ON_DEMAND $0.136/hr × 12h/day × 30 days × 2 instances ≈ $98/month saved per scanner type
