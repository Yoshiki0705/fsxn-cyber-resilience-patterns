# Performance Benchmark Suite

## Overview

Measures scan latency, event pipeline throughput, and quarantine response time
for the FSx for ONTAP Cyber Resilience architecture.

## Methodology

| Benchmark | Measurement | Load Profile |
|-----------|------------|--------------|
| Scan Latency | File write → ICAP → verdict → EventBridge | 100, 500, 1000 files/min |
| Pipeline Throughput | Max events/second before DLQ overflow | Increasing load until failure |
| Quarantine Response | EventBridge event → export policy restricted | Single event, isolated |

## Caveats

> **Important**: These benchmarks are run in a specific test environment and
> should NOT be interpreted as production performance guarantees. Results may
> vary based on FSx for ONTAP throughput capacity, scanner instance types,
> network configuration, and concurrent workload.

- Test environment: single-AZ, dedicated scanners, no competing workload
- FSx for ONTAP throughput: configurable (documented per run)
- Results include percentile distributions (p50, p95, p99)
- Each result includes estimated execution cost

## Usage

```bash
# Dry-run mode (no real infrastructure, for CI validation)
python3 benchmarks/run_benchmark.py --dry-run

# Full run (requires deployed environment)
python3 benchmarks/run_benchmark.py \
  --management-endpoint <fsx-management-dns> \
  --queue-url <sqs-queue-url> \
  --output results/run-$(date +%Y%m%d).json
```

## Output Format

```json
{
  "benchmark_id": "scan-latency-1000-fpm",
  "timestamp": "2026-07-15T10:00:00Z",
  "environment": {
    "instance_type": "c6g.xlarge",
    "fsx_throughput_mbps": 512,
    "region": "ap-northeast-1"
  },
  "results": {
    "p50_ms": 12,
    "p95_ms": 25,
    "p99_ms": 42,
    "max_ms": 85,
    "total_files": 1000,
    "duration_seconds": 60
  },
  "estimated_cost_usd": 3.50,
  "caveats": [
    "Single AZ deployment",
    "Synthetic workload (uniform file sizes)",
    "Not a production performance estimate"
  ]
}
```
