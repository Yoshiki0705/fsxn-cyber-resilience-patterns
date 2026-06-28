# Deep Instinct for NetApp ONTAP Integration

## Overview

Deep Instinct for NetApp ONTAP を FSx for ONTAP と統合し、AI 推論ベースの未知脅威防御を実現する。

## Architecture

See: [docs/deep-instinct/architecture.md](../../docs/deep-instinct/architecture.md)

## Prerequisites

- Deep Instinct for NetApp ONTAP license
- EC2 instance for DI Agent (in security subnet)
- FPolicy synchronous configuration on target SVM
- Network connectivity: FSx for ONTAP → DI Agent (ICAP 1344), DI Agent → Management (HTTPS 443)

## Deployment

Refer to `templates/scanning.yaml` (to be implemented) for CloudFormation deployment.
