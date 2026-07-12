#!/usr/bin/env bash
# -------------------------------------------------------------------
# demo-ad-join-svm.sh — Join an FSx for ONTAP SVM to Active Directory
#
# Resolves AD parameters from a CloudFormation stack or explicit flags,
# then calls aws fsx update-storage-virtual-machine to configure AD.
#
# Usage:
#   ./demo-ad-join-svm.sh --svm-id svm-xxx --ad-stack-name my-ad-stack
#   ./demo-ad-join-svm.sh --svm-id svm-xxx --domain corp.example.com \
#       --dns-ips 198.51.100.10,198.51.100.11
#
# Requirements:
#   - AWS CLI v2
#   - jq
#   - Valid AWS credentials with fsx:UpdateStorageVirtualMachine permission
# -------------------------------------------------------------------
set -euo pipefail

# -------------------------------------------------------------------
# Colors & Logging
# -------------------------------------------------------------------
readonly RED='\033[0;31m'
readonly GREEN='\033[0;32m'
readonly YELLOW='\033[0;33m'
readonly CYAN='\033[0;36m'
readonly NC='\033[0m'

log_info()  { echo -e "${GREEN}[INFO]${NC} $*"; }
log_warn()  { echo -e "${YELLOW}[WARN]${NC} $*"; }
log_error() { echo -e "${RED}[ERROR]${NC} $*" >&2; }
log_step()  { echo -e "${CYAN}[STEP]${NC} $*"; }

# -------------------------------------------------------------------
# Defaults
# -------------------------------------------------------------------
SVM_ID=""
AD_STACK_NAME=""
DOMAIN=""
DNS_IPS=""
AD_USERNAME="Admin"
AD_PASSWORD=""
NETBIOS_NAME=""
OU=""
REGION="${AWS_REGION:-ap-northeast-1}"
DRY_RUN=false
POLL_INTERVAL=20
POLL_MAX=30

# -------------------------------------------------------------------
# Usage
# -------------------------------------------------------------------
usage() {
    cat <<'EOF'
Usage: demo-ad-join-svm.sh [OPTIONS]

Join an FSx for ONTAP SVM to Active Directory.

REQUIRED:
  --svm-id ID               FSx for ONTAP Storage Virtual Machine ID (svm-xxx)

AD SOURCE (choose one):
  --ad-stack-name NAME      Resolve domain/DNS from CloudFormation stack outputs
  --domain FQDN             AD domain name (e.g., corp.example.com)
    --dns-ips IPs           Comma-separated DNS IPs (required with --domain)

OPTIONS:
  --ad-username USER        AD admin username (default: Admin)
  --ad-password PASS        AD admin password (prompted if not provided)
  --netbios-name NAME       NetBIOS name for the SVM (auto-generated if empty)
  --ou DN                   OU distinguished name for the computer object
                            (default: auto-generated from domain name)
  --region REGION           AWS region (default: $AWS_REGION or ap-northeast-1)
  --dry-run                 Show the API call without executing
  --help                    Show this help message

EXAMPLES:
  # From CloudFormation stack (Pattern A: created AD)
  ./demo-ad-join-svm.sh \
    --svm-id svm-0123456789abcdef0 \
    --ad-stack-name fsxn-cyber-resilience-demo-ad-dev

  # Explicit parameters (Pattern C: self-managed AD)
  ./demo-ad-join-svm.sh \
    --svm-id svm-0123456789abcdef0 \
    --domain onprem.example.com \
    --dns-ips 198.51.100.10,198.51.100.11 \
    --ou "OU=FSxComputers,DC=onprem,DC=example,DC=com"

  # Dry-run mode
  ./demo-ad-join-svm.sh \
    --svm-id svm-0123456789abcdef0 \
    --ad-stack-name my-stack \
    --dry-run

POLLING:
  After initiating the AD join, polls SVM status every 20s (max 30 attempts = 10 min).
  Exit codes: 0 = success, 1 = error, 2 = timeout (AD join still in progress).
EOF
    exit 0
}

# -------------------------------------------------------------------
# Parse Arguments
# -------------------------------------------------------------------
parse_args() {
    while [[ $# -gt 0 ]]; do
        case "$1" in
            --svm-id)       SVM_ID="$2"; shift 2 ;;
            --ad-stack-name) AD_STACK_NAME="$2"; shift 2 ;;
            --domain)       DOMAIN="$2"; shift 2 ;;
            --dns-ips)      DNS_IPS="$2"; shift 2 ;;
            --ad-username)  AD_USERNAME="$2"; shift 2 ;;
            --ad-password)  AD_PASSWORD="$2"; shift 2 ;;
            --netbios-name) NETBIOS_NAME="$2"; shift 2 ;;
            --ou)           OU="$2"; shift 2 ;;
            --region)       REGION="$2"; shift 2 ;;
            --dry-run)      DRY_RUN=true; shift ;;
            --help|-h)      usage ;;
            *)
                log_error "Unknown option: $1"
                echo "Run with --help for usage."
                exit 1
                ;;
        esac
    done
}

# -------------------------------------------------------------------
# Validation
# -------------------------------------------------------------------
validate() {
    local errors=0

    # Required tools
    for cmd in aws jq; do
        if ! command -v "$cmd" &>/dev/null; then
            log_error "Required command not found: $cmd"
            ((errors++))
        fi
    done

    # SVM ID required
    if [[ -z "$SVM_ID" ]]; then
        log_error "--svm-id is required"
        ((errors++))
    fi

    # Must have either stack name or explicit domain+dns
    if [[ -z "$AD_STACK_NAME" && -z "$DOMAIN" ]]; then
        log_error "Provide either --ad-stack-name or --domain + --dns-ips"
        ((errors++))
    fi

    if [[ -n "$DOMAIN" && -z "$DNS_IPS" ]]; then
        log_error "--dns-ips is required when --domain is specified"
        ((errors++))
    fi

    if [[ $errors -gt 0 ]]; then
        echo ""
        echo "Run with --help for usage."
        exit 1
    fi
}

# -------------------------------------------------------------------
# Resolve AD parameters from CloudFormation stack
# -------------------------------------------------------------------
resolve_from_stack() {
    log_step "Resolving AD parameters from stack: $AD_STACK_NAME"

    local outputs
    outputs=$(aws cloudformation describe-stacks \
        --stack-name "$AD_STACK_NAME" \
        --region "$REGION" \
        --query 'Stacks[0].Outputs' \
        --output json 2>/dev/null) || {
        log_error "Failed to describe stack: $AD_STACK_NAME"
        log_error "Ensure the stack exists and you have cloudformation:DescribeStacks permission."
        exit 1
    }

    # Extract outputs
    get_output() {
        echo "$outputs" | jq -r ".[] | select(.OutputKey==\"$1\") | .OutputValue // empty"
    }

    if [[ -z "$DOMAIN" ]]; then
        DOMAIN=$(get_output "DomainName")
        if [[ -z "$DOMAIN" ]]; then
            log_error "Could not resolve DomainName from stack outputs"
            exit 1
        fi
        log_info "Resolved domain: $DOMAIN"
    fi

    if [[ -z "$DNS_IPS" ]]; then
        DNS_IPS=$(get_output "DnsIpAddresses")
        if [[ -z "$DNS_IPS" ]]; then
            log_error "Could not resolve DnsIpAddresses from stack outputs"
            exit 1
        fi
        log_info "Resolved DNS IPs: $DNS_IPS"
    fi

    if [[ -z "$NETBIOS_NAME" ]]; then
        NETBIOS_NAME=$(get_output "NetBiosName")
        [[ -n "$NETBIOS_NAME" ]] && log_info "Resolved NetBIOS: $NETBIOS_NAME"
    fi
}

# -------------------------------------------------------------------
# Generate default OU from domain name
# -------------------------------------------------------------------
generate_default_ou() {
    if [[ -z "$OU" ]]; then
        # Convert corp.example.com → OU=Computers,DC=corp,DC=example,DC=com
        local dc_parts
        dc_parts=$(echo "$DOMAIN" | sed 's/\./,DC=/g')
        OU="OU=Computers,DC=${dc_parts}"
        log_info "Generated default OU: $OU"
    fi
}

# -------------------------------------------------------------------
# Generate NetBIOS name if not provided
# -------------------------------------------------------------------
generate_netbios() {
    if [[ -z "$NETBIOS_NAME" ]]; then
        # Use first segment of domain, uppercase, truncated to 15 chars
        NETBIOS_NAME=$(echo "$DOMAIN" | cut -d. -f1 | tr '[:lower:]' '[:upper:]' | cut -c1-15)
        log_info "Generated NetBIOS name: $NETBIOS_NAME"
    fi
}

# -------------------------------------------------------------------
# Prompt for password if not provided
# -------------------------------------------------------------------
prompt_password() {
    if [[ -z "$AD_PASSWORD" ]]; then
        if [[ "$DRY_RUN" == true ]]; then
            AD_PASSWORD="<DRY_RUN_PASSWORD_PLACEHOLDER>"
            return
        fi
        echo -n "Enter AD password for ${AD_USERNAME}@${DOMAIN}: "
        read -rs AD_PASSWORD
        echo ""
        if [[ -z "$AD_PASSWORD" ]]; then
            log_error "Password cannot be empty"
            exit 1
        fi
    fi
}

# -------------------------------------------------------------------
# Execute AD Join
# -------------------------------------------------------------------
execute_join() {
    # Build the ActiveDirectoryConfiguration JSON
    local ad_config
    ad_config=$(jq -n \
        --arg domain "$DOMAIN" \
        --arg ou "$OU" \
        --arg user "$AD_USERNAME" \
        --arg pass "$AD_PASSWORD" \
        --arg netbios "$NETBIOS_NAME" \
        --arg dns_ips "$DNS_IPS" \
        '{
            NetBiosName: $netbios,
            SelfManagedActiveDirectoryConfiguration: {
                DomainName: $domain,
                OrganizationalUnitDistinguishedName: $ou,
                UserName: $user,
                Password: $pass,
                DnsIps: ($dns_ips | split(","))
            }
        }')

    if [[ "$DRY_RUN" == true ]]; then
        log_warn "[DRY RUN] Would execute:"
        echo ""
        echo "aws fsx update-storage-virtual-machine \\"
        echo "  --storage-virtual-machine-id $SVM_ID \\"
        echo "  --region $REGION \\"
        echo "  --active-directory-configuration '$(echo "$ad_config" | jq -c 'del(.SelfManagedActiveDirectoryConfiguration.Password) | .SelfManagedActiveDirectoryConfiguration.Password = "***"')'"
        echo ""
        log_info "[DRY RUN] No changes made."
        exit 0
    fi

    log_step "Initiating AD join for SVM: $SVM_ID"
    log_info "  Domain:   $DOMAIN"
    log_info "  DNS IPs:  $DNS_IPS"
    log_info "  NetBIOS:  $NETBIOS_NAME"
    log_info "  OU:       $OU"
    log_info "  Username: $AD_USERNAME"
    echo ""

    local result
    result=$(aws fsx update-storage-virtual-machine \
        --storage-virtual-machine-id "$SVM_ID" \
        --active-directory-configuration "$ad_config" \
        --region "$REGION" \
        --output json 2>&1) || {
        log_error "Failed to initiate AD join:"
        echo "$result" >&2
        exit 1
    }

    log_info "AD join request submitted successfully."
    echo ""
}

# -------------------------------------------------------------------
# Poll for completion
# -------------------------------------------------------------------
poll_status() {
    log_step "Polling SVM AD join status (interval=${POLL_INTERVAL}s, max=${POLL_MAX} attempts)..."
    echo ""

    local attempt=0
    while [[ $attempt -lt $POLL_MAX ]]; do
        ((attempt++))

        local svm_info
        svm_info=$(aws fsx describe-storage-virtual-machines \
            --storage-virtual-machine-ids "$SVM_ID" \
            --region "$REGION" \
            --output json 2>/dev/null) || {
            log_warn "Failed to query SVM status (attempt $attempt/$POLL_MAX)"
            sleep "$POLL_INTERVAL"
            continue
        }

        local lifecycle
        lifecycle=$(echo "$svm_info" | jq -r '.StorageVirtualMachines[0].Lifecycle // "UNKNOWN"')

        local ad_status
        ad_status=$(echo "$svm_info" | jq -r '.StorageVirtualMachines[0].ActiveDirectoryConfiguration.SelfManagedActiveDirectoryConfiguration.DomainName // "not-joined"')

        printf "  [%2d/%d] Lifecycle: %-12s AD Domain: %s\n" "$attempt" "$POLL_MAX" "$lifecycle" "$ad_status"

        case "$lifecycle" in
            CREATED|MISCONFIGURED)
                # Still in progress or not yet updated
                ;;
            PENDING)
                # AD join in progress
                ;;
            *)
                # Check if AD is actually joined
                if [[ "$ad_status" != "not-joined" && "$ad_status" != "null" ]]; then
                    echo ""
                    log_info "SVM AD join completed successfully!"
                    log_info "  SVM ID:  $SVM_ID"
                    log_info "  Domain:  $ad_status"
                    log_info "  Status:  $lifecycle"
                    return 0
                fi
                ;;
        esac

        sleep "$POLL_INTERVAL"
    done

    echo ""
    log_warn "Polling timeout reached ($((POLL_MAX * POLL_INTERVAL))s)."
    log_warn "The AD join may still be in progress."
    log_warn "Check status: aws fsx describe-storage-virtual-machines --storage-virtual-machine-ids $SVM_ID --region $REGION"
    return 2
}

# -------------------------------------------------------------------
# Main
# -------------------------------------------------------------------
main() {
    parse_args "$@"
    validate

    echo ""
    log_info "=== FSx for ONTAP SVM AD Join Helper ==="
    echo ""

    # Resolve parameters
    if [[ -n "$AD_STACK_NAME" ]]; then
        resolve_from_stack
    fi

    generate_default_ou
    generate_netbios
    prompt_password

    # Execute
    execute_join

    # Poll
    poll_status
    exit $?
}

main "$@"
