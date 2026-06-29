# Parameters Directory

## 使い方 / Usage

CloudFormation テンプレートのパラメータ値を環境別に管理するディレクトリ。

## ファイル一覧

| File | Purpose | 変更必要箇所 |
|------|---------|------------|
| `dev.json` | 新規 VPC + 検証環境 (東京リージョン) | AZ をリージョンに合わせて変更 |
| `staging.json` | ステージング (NAT Gateway 有効) | AZ + VpcCidr |
| `existing-fsxn.json` | 既存 FSx for ONTAP 環境 (プレースホルダー) | 全値を実環境に合わせて変更 |

## リージョン別 AZ の指定

```bash
# 利用可能な AZ を確認
aws ec2 describe-availability-zones \
  --region <your-region> \
  --query 'AvailabilityZones[?State==`available`].ZoneName' \
  --output text
```

| Region | AvailabilityZone1 | AvailabilityZone2 |
|--------|-------------------|-------------------|
| ap-northeast-1 (東京) | `ap-northeast-1a` | `ap-northeast-1c` |
| us-east-1 (バージニア) | `us-east-1a` | `us-east-1b` |
| us-west-2 (オレゴン) | `us-west-2a` | `us-west-2b` |
| eu-west-1 (アイルランド) | `eu-west-1a` | `eu-west-1b` |
| ap-southeast-1 (シンガポール) | `ap-southeast-1a` | `ap-southeast-1b` |

## カスタムパラメータファイルの作成

```bash
# dev.json をベースにコピー
cp parameters/dev.json parameters/my-env.json

# 編集 (AZ, CIDR 等)
vi parameters/my-env.json

# デプロイ時に指定
aws cloudformation deploy --parameter-overrides file://parameters/my-env.json ...
# または deploy.sh を ENV=my-env で呼び出す (parameters/my-env.json が参照される)
```

## 注意事項

- `existing-fsxn.json` のプレースホルダー値 (`fs-0123...`) はサンプル。実際の ID に置き換えること
- `FsxAdminPassword` はパラメータファイルに含めず、Secrets Manager を使用すること（本番）
- `.env` ファイルは `.gitignore` 対象。パラメータファイルはリポジトリに含めてよい（機密値を含まない限り）
