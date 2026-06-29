# ONTAP Native Security Deep-Dive: ARP + FPolicy for FSx for ONTAP

> Configuring Autonomous Ransomware Protection and FPolicy for real-time file scanning on Amazon FSx for NetApp ONTAP.

## Introduction

This second article in the series dives into the storage-native security layer: how ARP detects ransomware by behavioral analysis, and how FPolicy enables real-time inline scanning via the ICAP protocol.

## ARP: Behavioral Ransomware Detection

### How ARP Works

ARP (Autonomous Ransomware Protection) monitors file-operation patterns at the storage layer:
- File rename entropy (random extensions like `.locked`, `.encrypted`)
- Bulk file modification rate
- File type changes (documents → encrypted blobs)

When anomalies are detected, ARP automatically:
1. Creates an ARP snapshot (recovery point before damage spreads)
2. Generates an EMS event (forwarded to our event pipeline)
3. Optionally blocks further writes (in active mode)

### ARP Lifecycle: Learning → Active

```
Day 0: Enable ARP in dry_run mode (learning)
         ↓ 30+ days of normal operation patterns
Day 30+: Transition to enabled (active protection)
```

In our architecture, the **ARP Lifecycle Manager** automates this:
- DynamoDB tracks learning start date per volume
- Daily EventBridge Scheduler triggers a Lambda check
- After 30 days: SNS notification → automatic transition

### Configuration via ONTAP REST API

```python
# Enable ARP in learning mode
client.enable_arp(volume_uuid, state="dry_run")

# After learning period, activate
client.enable_arp(volume_uuid, state="enabled")
```

Our CloudFormation Custom Resource handles this during stack creation.

## FPolicy: Real-Time File Event Processing

### The FPolicy → ICAP → Scanner Pattern

```
Client writes file → FSx for ONTAP → FPolicy Engine
    → ICAP request (TCP 1344) → Scanner (TrendAI / Deep Instinct)
    ← ICAP response (CLEAN / INFECTED)
    → Allow or Block the write
```

### FPolicy Configuration Components

| Component | Purpose |
|-----------|---------|
| **Engine** | External server definition (IP, port, sync/async) |
| **Event** | Which file operations to monitor (write, create, rename) |
| **Policy** | Ties engine + events together, sets mandatory flag |

### is_mandatory: The Availability vs Security Trade-off

| Setting | Behavior when scanner is down | Use case |
|---------|-------------------------------|----------|
| `false` (default) | Passthrough — allow writes | Availability-first |
| `true` | Block all writes | Security-first (accept downtime risk) |

Our architecture defaults to `false` with monitoring: if the scanner goes down, FPolicy passes through and CloudWatch alerts the team.

### Scan Target Filtering

Not every file needs scanning. Performance-optimized filtering:

```
Extensions to scan: exe, dll, scr, bat, ps1, docm, xlsm, zip, rar
Extensions to skip: log, tmp, csv, txt
Operation filter: first-write only (not every update)
Max file size: 100 MB (larger files timeout)
```

## Combining ARP and FPolicy

ARP and FPolicy serve complementary purposes:

| | ARP | FPolicy + Scanner |
|---|-----|------------------|
| Detection timing | Post-pattern (behavioral) | Pre-write (inline) |
| What it catches | Unknown ransomware patterns | Known + unknown malware |
| Performance impact | Near-zero (background analysis) | 5-30ms per write |
| Recovery aid | Automatic snapshot | Block before damage |

Both feed into the same EventBridge event pipeline for unified response.

## Implementation Reference

Full implementation with CloudFormation templates, Custom Resource handler, and configuration documentation:

- [FPolicy Configuration Guide](https://github.com/Yoshiki0705/fsxn-cyber-resilience-patterns/blob/main/docs/ontap-native/fpolicy-configuration.md)
- [ARP Configuration Guide](https://github.com/Yoshiki0705/fsxn-cyber-resilience-patterns/blob/main/docs/ontap-native/arp-configuration.md)
- [Security Config Custom Resource](https://github.com/Yoshiki0705/fsxn-cyber-resilience-patterns/blob/main/solutions/ontap-native/lambda/security_config_handler.py)

## 日本語サマリ

シリーズ第2回：ONTAP のストレージネイティブセキュリティ機能 (ARP + FPolicy) の設計と実装を解説。ARP の学習期間管理の自動化と、FPolicy/ICAP によるインラインスキャンのアーキテクチャパターンを紹介。

---

*Yoshiki Fujiwara — NetApp Cloud Solutions Architect, AWS Community Builder (Storage)*
