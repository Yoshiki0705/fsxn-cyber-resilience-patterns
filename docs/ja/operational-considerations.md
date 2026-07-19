# 運用上の注意事項

本プロジェクトを本番環境にデプロイする際の重要な注意事項。

> 詳細は英語版を参照してください: [Operational Considerations (EN)](../en/operational-considerations.md)

## 主要な注意点

| 項目 | 概要 |
|------|------|
| RTO/RPO | 環境固有のため本プロジェクトでは固定値を定義しない。検知〜遮断は 2 分以内（実測） |
| 誤検知対応 | TTL 自動解除スタックにより遮断期間を制限。非本番ユーザーで事前テスト必須 |
| 遮断範囲 | SMB/NFS 遮断は SVM 全体に影響（ボリューム単位ではない） |
| 同一サブネット制限 | NACL は同一サブネット内通信に無効。export-policy のみが遮断手段 |
| NTFS ボリューム | name-mapping deny は無効。AD アカウント無効化 or NTFS ACL 変更が必要 |
| Domain Admin | `FileSystemAdministratorsGroup` メンバーは name-mapping deny をバイパス |
| プライバシー | レスポンスログにユーザー名・IP が含まれる。適切なアクセス制御と保持ポリシーを適用 |
| AWS 固有 | オーケストレーション層は AWS 固有。ONTAP REST API パターンは移植可能 |
