---
inclusion: auto
---

# Security & Privacy — Public Repository Rules

This is a **public repository**. Every file committed is visible to the world.

## Never Commit

| Category | Examples |
|----------|----------|
| AWS Account IDs | 12-digit numbers |
| Real resource IDs | `vpc-0abc...`, `subnet-0abc...`, `sg-0abc...`, `fs-0abc...` |
| Real IP addresses | Any non-RFC5737 addresses |
| SSH key paths | `/Users/*/.../*.pem` |
| Personal file paths | `/Users/<username>/...` |
| Persona names | Use role descriptions only |
| Support case numbers | Reference by topic only |

## Required Placeholders

| Real Data | Placeholder |
|-----------|-------------|
| AWS Account ID | `123456789012` |
| VPC/Subnet/SG IDs | `vpc-0123456789abcdef0` |
| File System ID | `fs-0123456789abcdef0` |
| IP addresses | `10.0.x.x` or `<management-ip>` |
| SSH keys | `<your-ssh-key.pem>` |
| Personal paths | Relative or `${PROJECT_DIR}` |

## Supply-Chain Security

- All third-party Actions pinned to SHA hashes
- `actions/checkout` always sets `persist-credentials: false`
- gitleaks runs on every PR and push
- zizmor validates workflow files
- OpenSSF Scorecard runs weekly
