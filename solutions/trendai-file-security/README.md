# TrendAI Vision One — File Security Integration

## Overview

TrendAI Vision One — File Security を FSx for ONTAP と統合し、ファイル書き込み時のリアルタイムマルウェアスキャンを実現する。

Two integration patterns are supported:
1. **Vscan/ICAP (Primary)**: Real-time inline scanning on file write via FPolicy synchronous mode
2. **S3 AP (Secondary)**: Batch scanning of existing files via FSx for ONTAP S3 Access Points

## Architecture

See: [docs/trendai-file-security/](../../docs/trendai-file-security/)

## Prerequisites

- TrendAI Vision One — File Security license
- EC2 instance for Vscan server (in security subnet)
- FPolicy synchronous configuration on target SVM
- Network connectivity: FSx for ONTAP → Vscan (ICAP 1344), Vscan → TrendAI update (HTTPS 443)

## Deployment

Refer to `templates/scanning.yaml` (to be implemented) for CloudFormation deployment.
