# Tamperproof Snapshot Configuration

## 概要 / Overview

Tamperproof Snapshot（スナップショットロック）は、指定した Snapshot を保持期間中は
管理者を含む誰も削除できないようにする機能。ランサムウェアが管理者権限を奪取しても
復旧ポイントを保護する。

Tamperproof Snapshots (Snapshot Locking) prevent anyone — including administrators — from
deleting snapshots until the retention period expires. This protects recovery points even if
an attacker gains admin credentials.

## 前提条件

- FSx for ONTAP 9.12.1 以降
- SnapLock Compliance ライセンス（Tamperproof Snapshot の内部実装に必要）
- ボリュームレベルで設定

## 設定手順

### Step 1: Snapshot ポリシーの保持期間設定

```bash
ssh fsxadmin@<management-ip>

# Create a snapshot policy with locking
snapshot policy create -vserver svm-prod-dev \
  -policy tamperproof-hourly \
  -enabled true \
  -schedule1 hourly \
  -count1 24 \
  -snapmirror-label1 hourly \
  -retention-period1 "72 hours"
```

### Step 2: ボリュームに適用

```bash
# Apply the tamperproof snapshot policy to volume
volume modify -vserver svm-prod-dev \
  -volume vol_prod_dev \
  -snapshot-policy tamperproof-hourly

# Enable snapshot locking on the volume
volume snapshot locking enable -vserver svm-prod-dev -volume vol_prod_dev
```

### Step 3: 確認

```bash
# Verify snapshot locking is enabled
volume snapshot show -vserver svm-prod-dev -volume vol_prod_dev -fields snapshot-locking-enabled

# Show locked snapshots
volume snapshot show -vserver svm-prod-dev -volume vol_prod_dev -fields expiry-time
```

## REST API での設定

```bash
# Enable snapshot locking on volume
curl -X PATCH "https://<management-ip>/api/storage/volumes/{volume-uuid}" \
  -H "Content-Type: application/json" \
  -d '{
    "snapshot_locking_enabled": true
  }'

# Create a locked snapshot manually
curl -X POST "https://<management-ip>/api/storage/volumes/{volume-uuid}/snapshots" \
  -H "Content-Type: application/json" \
  -d '{
    "name": "tamperproof-manual-2026-06-25",
    "expiry_time": "2026-09-25T00:00:00Z"
  }'
```

## 推奨 Snapshot ポリシー（Cyber Resilience）

| Schedule | Count | Retention (Lock) | Purpose |
|----------|-------|------------------|---------|
| Hourly | 24 | 72 hours | 短期復旧（ランサムウェア検知後の immediate recovery） |
| Daily | 14 | 30 days | 中期復旧 |
| Weekly | 4 | 90 days | 長期復旧 + コンプライアンス |

## ARP Snapshot との関係

- ARP が自動作成する Snapshot も Tamperproof 化可能
- ARP Snapshot 名: `anti_ransomware_backup.*`
- ARP 検知 → 自動 Snapshot 作成 → ロック付与 の自動化を検討

## fsxadmin 権限での制約

- Snapshot locking の有効化/無効化: 可能
- ロック済み Snapshot の削除: **不可**（保持期間満了まで）
- ロック済み Snapshot の保持期間延長: 可能
- ロック済み Snapshot の保持期間短縮: **不可**

## 参照 / References

- [NetApp ONTAP — Tamper-proof Snapshots](https://docs.netapp.com/us-en/ontap/snaplock/snapshot-lock-concept.html)
- [FSx for ONTAP — Snapshot Locking](https://docs.aws.amazon.com/fsx/latest/ONTAPGuide/snapshot-locking.html)
