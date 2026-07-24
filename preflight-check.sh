#!/usr/bin/env bash
# =============================================================================
# preflight-check.sh — Pre-deployment validation for FSx for ONTAP Cyber Resilience
#
# Validates:
#   1. VPC Endpoint conflicts (duplicate S3 Gateway EP, existing Interface EPs)
#   2. Security Group rules (Lambda→FSx HTTPS, FSx→Scanner ICAP)
#   3. ONTAP S3 server presence on target SVM (structural conflict with S3 AP)
#
# Usage:
#   ./preflight-check.sh --vpc-id vpc-xxx --file-system-id fs-xxx [--region ap-northeast-1]
#   ./preflight-check.sh --vpc-id vpc-xxx  # VPC-only checks (no FSx)
#   ./preflight-check.sh --help
# =============================================================================
set -euo pipefail

# -----------------------------------------------------------------------------
# Configuration
# -----------------------------------------------------------------------------
VERSION="1.0.0"
REGION="${AWS_REGION:-ap-northeast-1}"
VPC_ID=""
FILE_SYSTEM_ID=""
SVM_NAME=""
VERBOSE=false

# Required Interface Endpoints for this architecture
REQUIRED_INTERFACE_EPS=("sqs" "secretsmanager" "kms" "sts")

# Colors
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[0;33m'
BLUE='\033[0;34m'
NC='\033[0m'

# Counters
PASS=0
WARN=0
FAIL=0

# -----------------------------------------------------------------------------
# Functions
# -----------------------------------------------------------------------------
usage() {
    cat <<EOF
preflight-check.sh v${VERSION}
Pre-deployment validation for FSx for ONTAP Cyber Resilience Patterns.

Usage:
  $0 --vpc-id <vpc-id> [OPTIONS]

Required:
  --vpc-id <vpc-id>           Target VPC ID

Optional:
  --file-system-id <fs-id>    FSx for ONTAP file system ID (enables ONTAP checks)
  --svm-name <svm-name>       SVM name to check for ONTAP S3 server conflict
  --region <region>           AWS region (default: \$AWS_REGION or ap-northeast-1)
  --verbose                   Show detailed output
  --help                      Show this help

Examples:
  # VPC-only checks (before FSx exists)
  $0 --vpc-id vpc-0123456789abcdef0

  # Full checks including FSx / ONTAP validation
  $0 --vpc-id vpc-0123456789abcdef0 \\
     --file-system-id fs-0123456789abcdef0 \\
     --svm-name svm1

  # Explicit region
  $0 --vpc-id vpc-0abc --file-system-id fs-0abc --region us-west-2
EOF
    exit 0
}

log_pass() { echo -e "  ${GREEN}[PASS]${NC} $*"; ((PASS++)); }
log_warn() { echo -e "  ${YELLOW}[WARN]${NC} $*"; ((WARN++)); }
log_fail() { echo -e "  ${RED}[FAIL]${NC} $*"; ((FAIL++)); }
log_info() { echo -e "  ${BLUE}[INFO]${NC} $*"; }
log_section() { echo -e "\n${BLUE}━━━ $* ━━━${NC}"; }

parse_args() {
    while [[ $# -gt 0 ]]; do
        case "$1" in
            --vpc-id)       VPC_ID="$2"; shift 2 ;;
            --file-system-id) FILE_SYSTEM_ID="$2"; shift 2 ;;
            --svm-name)     SVM_NAME="$2"; shift 2 ;;
            --region)       REGION="$2"; shift 2 ;;
            --verbose)      VERBOSE=true; shift ;;
            --help|-h)      usage ;;
            *) echo "Unknown option: $1"; usage ;;
        esac
    done

    if [[ -z "$VPC_ID" ]]; then
        echo -e "${RED}Error: --vpc-id is required${NC}"
        echo ""
        usage
    fi
}

check_prerequisites() {
    log_section "Prerequisites"

    if ! command -v aws &>/dev/null; then
        log_fail "AWS CLI not found. Install: https://aws.amazon.com/cli/"
        exit 1
    fi
    log_pass "AWS CLI available"

    if ! command -v jq &>/dev/null; then
        log_fail "jq not found. Install: brew install jq (macOS) / apt install jq (Linux)"
        exit 1
    fi
    log_pass "jq available"

    if ! aws sts get-caller-identity --region "$REGION" &>/dev/null; then
        log_fail "AWS credentials not configured or expired"
        exit 1
    fi

    local identity
    identity=$(aws sts get-caller-identity --region "$REGION" --output json)
    local arn
    arn=$(echo "$identity" | jq -r '.Arn')
    log_pass "AWS credentials valid: $arn"
    log_info "Region: $REGION"
}

# -----------------------------------------------------------------------------
# Check 1: VPC Endpoint Conflicts
# -----------------------------------------------------------------------------
check_vpc_endpoints() {
    log_section "VPC Endpoint Conflict Check"

    local endpoints
    endpoints=$(aws ec2 describe-vpc-endpoints \
        --filters "Name=vpc-id,Values=${VPC_ID}" \
        --region "$REGION" \
        --output json 2>/dev/null)

    local ep_count
    ep_count=$(echo "$endpoints" | jq '.VpcEndpoints | length')
    log_info "Found $ep_count existing VPC Endpoint(s) in $VPC_ID"

    # --- S3 Gateway Endpoint ---
    local s3_gw_eps
    s3_gw_eps=$(echo "$endpoints" | jq -r \
        '[.VpcEndpoints[] | select(.ServiceName | endswith(".s3")) | select(.VpcEndpointType == "Gateway")] | length')

    if [[ "$s3_gw_eps" -gt 0 ]]; then
        log_warn "S3 Gateway Endpoint already exists in VPC"
        log_info "  → network.yaml will fail if it tries to create another S3 Gateway EP"
        log_info "  → Resolution: Use UseExistingVpc=true and skip S3 EP creation,"
        log_info "    or ensure existing EP's route tables cover required subnets"

        # Check route table associations
        if [[ "$VERBOSE" == "true" ]]; then
            local s3_ep_id
            s3_ep_id=$(echo "$endpoints" | jq -r \
                '.VpcEndpoints[] | select(.ServiceName | endswith(".s3")) | select(.VpcEndpointType == "Gateway") | .VpcEndpointId')
            local rt_count
            rt_count=$(echo "$endpoints" | jq -r \
                ".VpcEndpoints[] | select(.VpcEndpointId == \"$s3_ep_id\") | .RouteTableIds | length")
            log_info "  Route tables associated: $rt_count"
        fi
    else
        log_pass "No existing S3 Gateway Endpoint (safe to create)"
    fi

    # --- Interface Endpoints ---
    for svc in "${REQUIRED_INTERFACE_EPS[@]}"; do
        local svc_full="com.amazonaws.${REGION}.${svc}"
        local existing
        existing=$(echo "$endpoints" | jq -r \
            "[.VpcEndpoints[] | select(.ServiceName == \"$svc_full\") | select(.VpcEndpointType == \"Interface\")] | length")

        if [[ "$existing" -gt 0 ]]; then
            # Check PrivateDnsEnabled
            local private_dns
            private_dns=$(echo "$endpoints" | jq -r \
                ".VpcEndpoints[] | select(.ServiceName == \"$svc_full\") | .PrivateDnsEnabled")

            if [[ "$private_dns" == "true" ]]; then
                log_warn "${svc} Interface Endpoint already exists (PrivateDnsEnabled=true)"
                log_info "  → network.yaml cannot create a duplicate; share the existing EP"
                log_info "  → Ensure its SG allows HTTPS/443 from VPC CIDR"
            else
                log_fail "${svc} Interface Endpoint exists but PrivateDnsEnabled=FALSE"
                log_info "  → Lambda SDK calls will fail without Private DNS"
                log_info "  → Fix: Enable Private DNS on the existing endpoint, or"
                log_info "    configure endpoint URL override in Lambda environment"
            fi
        else
            log_pass "No existing ${svc} Interface Endpoint (safe to create)"
        fi
    done
}

# -----------------------------------------------------------------------------
# Check 2: Security Group Rules
# -----------------------------------------------------------------------------
check_security_groups() {
    log_section "Security Group Validation"

    if [[ -z "$FILE_SYSTEM_ID" ]]; then
        log_info "Skipping SG checks (no --file-system-id provided)"
        return
    fi

    # Get FSx ENI info to find associated Security Groups
    local fs_info
    fs_info=$(aws fsx describe-file-systems \
        --file-system-ids "$FILE_SYSTEM_ID" \
        --region "$REGION" \
        --output json 2>/dev/null)

    if [[ $(echo "$fs_info" | jq '.FileSystems | length') -eq 0 ]]; then
        log_fail "File system $FILE_SYSTEM_ID not found in region $REGION"
        return
    fi

    local fs_vpc
    fs_vpc=$(echo "$fs_info" | jq -r '.FileSystems[0].VpcId')
    if [[ "$fs_vpc" != "$VPC_ID" ]]; then
        log_fail "FSx for ONTAP ($FILE_SYSTEM_ID) is in VPC $fs_vpc, not $VPC_ID"
        return
    fi
    log_pass "FSx for ONTAP is in target VPC"

    # Get Network Interface IDs from FSx
    local eni_ids
    eni_ids=$(echo "$fs_info" | jq -r '.FileSystems[0].NetworkInterfaceIds // [] | .[]' 2>/dev/null)

    if [[ -z "$eni_ids" ]]; then
        log_warn "No network interfaces found for FSx (may still be creating)"
        return
    fi

    # Get Security Groups from the first ENI
    local first_eni
    first_eni=$(echo "$eni_ids" | head -1)
    local fsx_sgs
    fsx_sgs=$(aws ec2 describe-network-interfaces \
        --network-interface-ids "$first_eni" \
        --region "$REGION" \
        --query 'NetworkInterfaces[0].Groups[*].GroupId' \
        --output json 2>/dev/null)

    log_info "FSx Security Groups: $(echo "$fsx_sgs" | jq -r 'join(", ")')"

    # Check each FSx SG for required ingress rules
    for sg_id in $(echo "$fsx_sgs" | jq -r '.[]'); do
        local sg_rules
        sg_rules=$(aws ec2 describe-security-group-rules \
            --filters "Name=group-id,Values=$sg_id" \
            --region "$REGION" \
            --output json 2>/dev/null)

        # Check HTTPS/443 ingress (for Lambda → ONTAP REST API)
        local https_ingress
        https_ingress=$(echo "$sg_rules" | jq \
            '[.SecurityGroupRules[] | select(.IsEgress == false) | select(.FromPort <= 443 and .ToPort >= 443)] | length')

        if [[ "$https_ingress" -gt 0 ]]; then
            log_pass "SG $sg_id allows inbound HTTPS/443 (ONTAP REST API access)"
        else
            log_fail "SG $sg_id missing inbound HTTPS/443 rule"
            log_info "  → Lambda functions cannot reach ONTAP REST API"
            log_info "  → Add: TCP/443 from Lambda Security Group"
        fi

        # Check ICAP/1344 egress (for FPolicy → Scanner)
        local icap_egress
        icap_egress=$(echo "$sg_rules" | jq \
            '[.SecurityGroupRules[] | select(.IsEgress == true) | select(.FromPort <= 1344 and .ToPort >= 1344)] | length')

        if [[ "$icap_egress" -gt 0 ]]; then
            log_pass "SG $sg_id allows outbound ICAP/1344 (FPolicy to scanner)"
        else
            log_warn "SG $sg_id missing outbound ICAP/1344 rule"
            log_info "  → FPolicy sync scanning will not work without ICAP egress"
            log_info "  → Add: TCP/1344 to scanner Security Group"
            log_info "  → Skip if using async FPolicy only"
        fi
    done
}

# -----------------------------------------------------------------------------
# Check 3: ONTAP S3 Server Conflict
# -----------------------------------------------------------------------------
check_ontap_s3_server() {
    log_section "ONTAP S3 Server Conflict Check"

    if [[ -z "$FILE_SYSTEM_ID" ]]; then
        log_info "Skipping ONTAP S3 check (no --file-system-id provided)"
        return
    fi

    if [[ -z "$SVM_NAME" ]]; then
        log_info "Skipping ONTAP S3 check (no --svm-name provided)"
        log_info "  → Provide --svm-name to check for S3 AP structural conflict"
        return
    fi

    # Get management endpoint
    local mgmt_endpoint
    mgmt_endpoint=$(aws fsx describe-file-systems \
        --file-system-ids "$FILE_SYSTEM_ID" \
        --region "$REGION" \
        --query 'FileSystems[0].OntapConfiguration.Endpoints.Management.DNSName' \
        --output text 2>/dev/null)

    if [[ -z "$mgmt_endpoint" || "$mgmt_endpoint" == "None" ]]; then
        log_warn "Cannot determine ONTAP management endpoint"
        log_info "  → Manual check: Verify no ONTAP S3 server on SVM '$SVM_NAME'"
        log_info "  → ONTAP CLI: vserver object-store-server show -vserver $SVM_NAME"
        return
    fi

    log_info "Management endpoint: $mgmt_endpoint"
    log_info "Checking ONTAP S3 server on SVM: $SVM_NAME"

    # Attempt ONTAP REST API call (requires fsxadmin credentials)
    # This is a best-effort check — if credentials are not available, provide guidance
    local secret_arn
    secret_arn=$(aws secretsmanager list-secrets \
        --region "$REGION" \
        --filters "Key=name,Values=fsxn-cyber-resilience-fsxadmin" \
        --query 'SecretList[0].ARN' \
        --output text 2>/dev/null)

    if [[ -z "$secret_arn" || "$secret_arn" == "None" ]]; then
        log_warn "fsxadmin credentials not found in Secrets Manager"
        log_info "  → Cannot perform automated ONTAP S3 server check"
        log_info "  → Manual verification required before creating S3 Access Points:"
        log_info ""
        log_info "    ssh fsxadmin@${mgmt_endpoint}"
        log_info "    vserver object-store-server show -vserver ${SVM_NAME}"
        log_info ""
        log_info "  → If an S3 server exists, FSx for ONTAP S3 AP creation will fail with:"
        log_info "    'existing ONTAP object storage server on SVM'"
        log_info "  → This is a structural conflict (not a timing issue). Resolution:"
        log_info "    1. Use a different SVM without ONTAP S3 server, OR"
        log_info "    2. Delete the ONTAP S3 server (data loss if buckets exist)"
        return
    fi

    # Retrieve credentials
    local creds
    creds=$(aws secretsmanager get-secret-value \
        --secret-id "$secret_arn" \
        --region "$REGION" \
        --query 'SecretString' \
        --output text 2>/dev/null)

    local username password
    username=$(echo "$creds" | jq -r '.username // "fsxadmin"')
    password=$(echo "$creds" | jq -r '.password')

    if [[ -z "$password" ]]; then
        log_warn "Could not extract password from secret"
        return
    fi

    # Call ONTAP REST API to check S3 services
    local s3_response
    s3_response=$(curl -sk -u "${username}:${password}" \
        "https://${mgmt_endpoint}/api/protocols/s3/services?svm.name=${SVM_NAME}&fields=name,enabled" \
        --connect-timeout 10 \
        --max-time 30 2>/dev/null) || true

    if [[ -z "$s3_response" ]]; then
        log_warn "Cannot reach ONTAP REST API at $mgmt_endpoint"
        log_info "  → Ensure network connectivity (VPN, SG rules, DNS resolution)"
        log_info "  → Manual check: vserver object-store-server show -vserver $SVM_NAME"
        return
    fi

    local s3_count
    s3_count=$(echo "$s3_response" | jq '.num_records // 0' 2>/dev/null)

    if [[ "$s3_count" -gt 0 ]]; then
        local s3_name s3_enabled
        s3_name=$(echo "$s3_response" | jq -r '.records[0].name // "unknown"')
        s3_enabled=$(echo "$s3_response" | jq -r '.records[0].enabled // false')

        log_fail "ONTAP S3 server found on SVM '$SVM_NAME': name=$s3_name, enabled=$s3_enabled"
        log_info "  → FSx for ONTAP S3 Access Point creation will FAIL on this SVM"
        log_info "  → This is a STRUCTURAL conflict — retrying will not help"
        log_info "  → Resolution options:"
        log_info "    1. (Preferred) Use a different SVM without ONTAP S3 server"
        log_info "    2. Delete the S3 server: DELETE /api/protocols/s3/services/{uuid}"
        log_info "       WARNING: delete_all=true required if buckets exist (data loss)"
    else
        log_pass "No ONTAP S3 server on SVM '$SVM_NAME' (safe for S3 AP)"
    fi
}

# -----------------------------------------------------------------------------
# Check 4: FSx for ONTAP status
# -----------------------------------------------------------------------------
check_fsx_status() {
    log_section "FSx for ONTAP Status"

    if [[ -z "$FILE_SYSTEM_ID" ]]; then
        log_info "Skipping FSx status check (no --file-system-id provided)"
        return
    fi

    local fs_info
    fs_info=$(aws fsx describe-file-systems \
        --file-system-ids "$FILE_SYSTEM_ID" \
        --region "$REGION" \
        --output json 2>/dev/null)

    local lifecycle
    lifecycle=$(echo "$fs_info" | jq -r '.FileSystems[0].Lifecycle')
    local ontap_config
    ontap_config=$(echo "$fs_info" | jq '.FileSystems[0].OntapConfiguration')
    local deployment_type
    deployment_type=$(echo "$ontap_config" | jq -r '.DeploymentType')
    local throughput
    throughput=$(echo "$ontap_config" | jq -r '.ThroughputCapacity')

    if [[ "$lifecycle" == "AVAILABLE" ]]; then
        log_pass "File system status: AVAILABLE"
    else
        log_fail "File system status: $lifecycle (must be AVAILABLE for deployment)"
        return
    fi

    log_info "Deployment type: $deployment_type"
    log_info "Throughput capacity: ${throughput} MBps"

    # Check automatic backups (relevant for volume deletion behavior)
    local backup_days
    backup_days=$(echo "$fs_info" | jq -r '.FileSystems[0].OntapConfiguration.AutomaticBackupRetentionDays // 0')
    if [[ "$backup_days" -gt 0 ]]; then
        log_info "Automatic backups: enabled (${backup_days} day retention)"
        log_info "  → Note: Volumes with backups cannot be deleted via ONTAP REST API"
        log_info "    (SnapMirror relationship managed by FSx — use FSx API for deletion)"
    else
        log_info "Automatic backups: disabled"
    fi
}

# -----------------------------------------------------------------------------
# Summary
# -----------------------------------------------------------------------------
print_summary() {
    log_section "Summary"
    echo ""
    echo -e "  ${GREEN}PASS${NC}: $PASS"
    echo -e "  ${YELLOW}WARN${NC}: $WARN"
    echo -e "  ${RED}FAIL${NC}: $FAIL"
    echo ""

    if [[ $FAIL -gt 0 ]]; then
        echo -e "  ${RED}Result: BLOCKED — resolve FAIL items before deployment${NC}"
        echo ""
        exit 1
    elif [[ $WARN -gt 0 ]]; then
        echo -e "  ${YELLOW}Result: PROCEED WITH CAUTION — review WARN items${NC}"
        echo ""
        exit 0
    else
        echo -e "  ${GREEN}Result: READY TO DEPLOY${NC}"
        echo ""
        exit 0
    fi
}

# -----------------------------------------------------------------------------
# Main
# -----------------------------------------------------------------------------
main() {
    echo ""
    echo "╔══════════════════════════════════════════════════════════════╗"
    echo "║  FSx for ONTAP Cyber Resilience — Pre-flight Check v${VERSION}  ║"
    echo "╚══════════════════════════════════════════════════════════════╝"
    echo ""
    echo "  VPC:             $VPC_ID"
    echo "  File System:     ${FILE_SYSTEM_ID:-"(not specified)"}"
    echo "  SVM:             ${SVM_NAME:-"(not specified)"}"
    echo "  Region:          $REGION"

    check_prerequisites
    check_vpc_endpoints
    check_security_groups
    check_ontap_s3_server
    check_fsx_status
    print_summary
}

parse_args "$@"
main
