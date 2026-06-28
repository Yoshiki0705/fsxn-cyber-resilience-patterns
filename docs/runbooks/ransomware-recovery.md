# Ransomware Recovery Runbook

## 概要 / Overview

FSx for ONTAP 環境でランサムウェア攻撃を受けた場合の、検知→封じ込め→復旧→事後対応の全手順。

## 判断フローチャート / Decision Flowchart

```mermaid
flowchart TD
    START[Alert Received] --> ASSESS{Alert Source?}
    
    ASSESS -->|ARP| ARP_CHECK[Review ARP snapshot created]
    ASSESS -->|Scanner| SCAN_CHECK[Review scan verdict details]
    ASSESS -->|Manual report| MANUAL[Gather indicators]
    
    ARP_CHECK --> CONFIRM{Confirmed attack?}
    SCAN_CHECK --> CONFIRM
    MANUAL --> CONFIRM
    
    CONFIRM -->|Yes - Active attack| CONTAIN[CONTAIN: Restrict access immediately]
    CONFIRM -->|Suspicious - Need investigation| INVESTIGATE[INVESTIGATE: Create FlexClone]
    CONFIRM -->|False positive| FP[Mark as FP, restore access]
    
    CONTAIN --> SNAPSHOT[Create tamperproof snapshot]
    SNAPSHOT --> SCOPE[Assess scope: which volumes affected?]
    SCOPE --> RECOVERY{Recovery path?}
    
    RECOVERY -->|ARP Snapshot available| RESTORE_ARP[SnapRestore from ARP snapshot]
    RECOVERY -->|Pre-attack snapshot| RESTORE_SNAP[SnapRestore from clean snapshot]
    RECOVERY -->|DR copy available| RESTORE_DR[Failover to SnapMirror target]
    
    RESTORE_ARP --> VERIFY[Verify restored data integrity]
    RESTORE_SNAP --> VERIFY
    RESTORE_DR --> VERIFY
    
    VERIFY --> REOPEN[Re-enable access (export policy)]
    REOPEN --> POSTMORTEM[Post-incident review]
    
    INVESTIGATE --> CLONE[Create read-only FlexClone]
    CLONE --> FORENSIC[Forensic analysis on clone]
    FORENSIC --> CONFIRM
```

## Phase 1: 検知 (Detection)

### ARP アラート受信時

```bash
# Check ARP alert status
ssh fsxadmin@<management-ip>
security anti-ransomware volume show -vserver svm-prod-dev -fields state,attack-detected

# List ARP-created snapshots
volume snapshot show -vserver svm-prod-dev -volume vol_prod_dev -snapshot anti_ransomware_backup*
```

### Scanner アラート受信時

- EventBridge → Step Functions で自動隔離が既に実行されている場合あり
- Step Functions コンソールで Quarantine Workflow の実行状態を確認

## Phase 2: 封じ込め (Containment)

### Immediate: Export Policy 制限（アクセスブロック）

```bash
# Create a restrictive export policy (deny all clients)
vserver export-policy rule create -vserver svm-prod-dev \
  -policyname quarantine_policy \
  -ruleindex 1 \
  -protocol any \
  -clientmatch 0.0.0.0/0 \
  -rorule never \
  -rwrule never \
  -superuser none

# Apply quarantine policy to affected volume
volume modify -vserver svm-prod-dev -volume vol_prod_dev -policy quarantine_policy
```

### Tamperproof Snapshot 作成

```bash
# Create a tamperproof snapshot of current state (evidence preservation)
volume snapshot create -vserver svm-prod-dev -volume vol_prod_dev \
  -snapshot "evidence-$(date +%Y%m%d-%H%M%S)" \
  -snapmirror-label evidence \
  -expiry-time "$(date -d '+90 days' --iso-8601=seconds)"
```

## Phase 3: 調査 (Investigation)

### FlexClone による安全な調査環境

```bash
# Create read-only clone for forensic analysis
volume clone create -vserver svm-prod-dev \
  -flexclone forensic_clone_$(date +%Y%m%d) \
  -parent-volume vol_prod_dev \
  -parent-snapshot anti_ransomware_backup.2026-06-25_1030 \
  -junction-path /forensics

# Mount clone (read-only) for analysis
# Forensics team can access /forensics via NFS
```

### 証拠保全 (Chain of Custody)

1. FlexClone 作成時刻・元 Snapshot を記録
2. **FlexClone のデータ整合性を検証**:
   ```bash
   # Calculate SHA-256 hash of key evidence files
   find /mnt/forensics -type f -exec sha256sum {} \; > /tmp/forensic-manifest-$(date +%Y%m%d).sha256
   
   # Store manifest in SnapLock volume (immutable)
   cp /tmp/forensic-manifest-*.sha256 /mnt/compliance/evidence/
   ```
3. アクセスログを SnapLock ボリュームにコピー
4. 調査担当者のアクセスを監査ログで記録
5. 調査完了後、FlexClone を保持（削除しない）
6. **Evidence integrity log** に以下を記録（改ざん防止）:
   - Clone作成日時、元Snapshot名、作成者
   - SHA-256マニフェストのハッシュ値
   - 関与した調査担当者名一覧

## Phase 4: 復旧 (Recovery)

### Option A: ARP Snapshot からの復旧

```bash
# Identify clean ARP snapshot
volume snapshot show -vserver svm-prod-dev -volume vol_prod_dev \
  -snapshot anti_ransomware_backup* -fields create-time

# Restore from ARP snapshot
volume snapshot restore -vserver svm-prod-dev -volume vol_prod_dev \
  -snapshot anti_ransomware_backup.2026-06-25_0900
```

### Option B: 通常 Snapshot からの復旧

```bash
# List available snapshots (find last known clean)
volume snapshot show -vserver svm-prod-dev -volume vol_prod_dev -fields create-time

# Restore from clean snapshot
volume snapshot restore -vserver svm-prod-dev -volume vol_prod_dev \
  -snapshot hourly.2026-06-25_0800
```

### Option C: SnapMirror DR からの復旧

```bash
# Break SnapMirror relationship (make destination writable)
snapmirror break -destination-path svm-dr:vol_prod_dr

# Verify data integrity on DR copy
# Mount and validate with business owners

# Reverse resync (when original is ready)
snapmirror resync -source-path svm-dr:vol_prod_dr -destination-path svm-prod-dev:vol_prod_dev
```

### アクセス復旧

```bash
# Restore original export policy
volume modify -vserver svm-prod-dev -volume vol_prod_dev -policy default_export_policy

# Verify client access
showmount -e <svm-management-ip>
```

## Phase 5: 事後対応 (Post-Incident)

### 必須アクション

- [ ] インシデントレポート作成（タイムライン、影響範囲、復旧時間）
- [ ] ARP 学習データが汚染されていないか確認
- [ ] FPolicy フィルタの見直し（攻撃ベクトルを追加）
- [ ] スキャンサーバーのシグネチャ/モデル更新確認
- [ ] 影響を受けたユーザーへの通知
- [ ] 再発防止策の検討・実装

### DR テスト（年次）

| テスト項目 | 頻度 | 担当 |
|-----------|------|------|
| ARP Snapshot からの復旧演習 | 四半期 | ストレージ管理者 |
| FlexClone フォレンジック演習 | 半年 | セキュリティチーム |
| SnapMirror フェイルオーバー | 年次 | インフラチーム |
| Full ransomware simulation (EICAR) | 年次 | セキュリティチーム + 全関係者 |

## Contact & Escalation

| Level | Condition | Contact |
|-------|-----------|---------|
| L1 | ARP alert (single volume) | Security Operations |
| L2 | Multiple volumes / active encryption | Security Manager + Storage Admin |
| L3 | Business-critical data affected | CISO + Executive team |
| External | Law enforcement needed | Legal team + External IR firm |
