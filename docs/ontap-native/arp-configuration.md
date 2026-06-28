# ARP (Autonomous Ransomware Protection) Configuration

## 概要 / Overview

ONTAP ARP はファイルアクセスパターンの機械学習分析により、ランサムウェアによる異常な暗号化行動を検知する。
検知時に自動で保護 Snapshot を作成し、アラートを発行する。

ARP analyzes file access patterns using machine learning to detect abnormal encryption behavior
indicative of ransomware. Upon detection, it automatically creates a protective snapshot and raises an alert.

## 前提条件 / Prerequisites

- FSx for ONTAP 9.10.1 以降（推奨: 9.15.1+ で ARP/AI 強化版）
- NFS または SMB ボリューム（FlexVol または FlexGroup）
- ボリュームが通常のワークロードで使用されていること（学習データ必要）

## 有効化手順 / Enable Procedure

### Step 1: SVM レベルで ARP を有効化

```bash
# SSH to FSx management endpoint
ssh fsxadmin@<management-ip>

# Enable ARP on the SVM
security anti-ransomware vserver enable -vserver svm-prod-dev
```

### Step 2: ボリュームレベルで学習モード有効化

```bash
# Enable ARP in learning mode (MUST run for 30+ days before active)
security anti-ransomware volume enable -vserver svm-prod-dev -volume vol_prod_dev -state dry-run
```

> **Important**: 学習モード（dry-run）で最低30日間運用し、正常なワークロードパターンを学習させる。
> この期間中は検知のみで、ブロックやアラートは発行されない。

### Step 3: アクティブモードへ移行

```bash
# After 30+ days of learning, switch to active mode
security anti-ransomware volume enable -vserver svm-prod-dev -volume vol_prod_dev -state active

# Verify status
security anti-ransomware volume show -vserver svm-prod-dev
```

## ONTAP REST API での設定

### 学習モード有効化

```bash
curl -X PATCH "https://<management-ip>/api/security/anti-ransomware/volumes/{volume-uuid}" \
  -H "Authorization: Basic $(echo -n fsxadmin:<password> | base64)" \
  -H "Content-Type: application/json" \
  -d '{"state": "dry_run"}'
```

### アクティブモード移行

```bash
curl -X PATCH "https://<management-ip>/api/security/anti-ransomware/volumes/{volume-uuid}" \
  -H "Authorization: Basic $(echo -n fsxadmin:<password> | base64)" \
  -H "Content-Type: application/json" \
  -d '{"state": "enabled"}'
```

### ステータス確認

```bash
curl -X GET "https://<management-ip>/api/security/anti-ransomware/volumes?fields=*" \
  -H "Authorization: Basic $(echo -n fsxadmin:<password> | base64)"
```

## CloudFormation Custom Resource による自動化

ARP 設定は CloudFormation ネイティブリソースでサポートされないため、Lambda-backed Custom Resource で自動化可能。

```yaml
# Custom Resource Lambda (概念)
# 1. Secrets Manager から fsxadmin 認証情報取得
# 2. ONTAP REST API で ARP 有効化
# 3. Lambda タイムアウト: 300秒
# 4. Create/Update/Delete ハンドラ実装
```

> **制約**: Custom Resource は ARP の初期有効化（learning mode）まで。
> Active mode への移行は30日後に手動または別の Step Functions ワークフローで実行する。

## 検知時の動作

1. ARP がファイル操作パターンの異常を検知
2. 自動で ARP Snapshot を作成（`anti_ransomware_backup.*`）
3. EMS (Event Management System) イベント発行
4. 管理者がアラートを確認し、true positive / false positive を判定

## 運用考慮事項

### 偽陽性 (False Positive) 対策

- 学習期間は最低30日確保（推奨: 45日）
- 大量ファイル操作が予想される場合（バッチ処理、バックアップ等）は事前にホワイトリスト設定
- 段階的にボリュームを Active 化（一度に全ボリュームを切り替えない）

### fsxadmin 権限での制約

- ARP の有効化・設定変更は fsxadmin で可能
- ARP の学習データリセットは AWS サポートリクエストが必要な場合あり
- cluster admin レベルの操作は不可

## 参照 / References

- [NetApp ONTAP — Autonomous Ransomware Protection](https://docs.netapp.com/us-en/ontap/anti-ransomware/)
- [FSx for ONTAP — ARP Documentation](https://docs.aws.amazon.com/fsx/latest/ONTAPGuide/arp.html)
