#!/usr/bin/env bash
# Deploy FSx for ONTAP Cyber Resilience stacks.
#
# Usage:
#   ./scripts/deploy.sh [ENV] [STACK]
#
# Examples:
#   ./scripts/deploy.sh dev              # Deploy all stacks to dev
#   ./scripts/deploy.sh staging network  # Deploy only network stack to staging
#   ./scripts/deploy.sh production       # Deploy all stacks to production (confirms)

set -euo pipefail

# -------------------------------------------------------------------
# Configuration
# -------------------------------------------------------------------
ENV="${1:-dev}"
STACK="${2:-all}"
REGION="${AWS_REGION:-ap-northeast-1}"
PROJECT_NAME="fsxn-cyber-resilience"
SCRIPT_DIR="$(cd "$(dirname "$0")" && pwd)"
PROJECT_DIR="$(dirname "$SCRIPT_DIR")"

# Colors
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[0;33m'
NC='\033[0m'

# -------------------------------------------------------------------
# Functions
# -------------------------------------------------------------------
log_info()  { echo -e "${GREEN}[INFO]${NC} $*"; }
log_warn()  { echo -e "${YELLOW}[WARN]${NC} $*"; }
log_error() { echo -e "${RED}[ERROR]${NC} $*"; }

validate_env() {
    if [[ ! "$ENV" =~ ^(dev|staging|production)$ ]]; then
        log_error "Invalid environment: $ENV (must be dev|staging|production)"
        exit 1
    fi
}

confirm_production() {
    if [[ "$ENV" == "production" ]]; then
        log_warn "You are deploying to PRODUCTION!"
        read -rp "Type 'yes' to confirm: " confirm
        if [[ "$confirm" != "yes" ]]; then
            log_info "Aborted."
            exit 0
        fi
    fi
}

check_prerequisites() {
    log_info "Checking prerequisites..."

    if ! command -v aws &>/dev/null; then
        log_error "AWS CLI not found. Install: https://aws.amazon.com/cli/"
        exit 1
    fi

    # Verify credentials
    if ! aws sts get-caller-identity --region "$REGION" &>/dev/null; then
        log_error "AWS credentials not configured or expired."
        exit 1
    fi

    local identity
    identity=$(aws sts get-caller-identity --region "$REGION" --output json)
    log_info "Deploying as: $(echo "$identity" | python3 -c 'import sys,json; print(json.load(sys.stdin)["Arn"])')"
}

lint_templates() {
    log_info "Linting templates..."
    cd "$PROJECT_DIR"
    if command -v cfn-lint &>/dev/null; then
        cfn-lint templates/*.yaml || test $? -le 12
    else
        log_warn "cfn-lint not found, skipping lint."
    fi
}

deploy_stack() {
    local stack_name="$1"
    local template="$2"
    local params="${3:-}"

    log_info "Deploying stack: $stack_name"

    local cmd=(
        aws cloudformation deploy
        --template-file "$PROJECT_DIR/templates/$template"
        --stack-name "$stack_name"
        --region "$REGION"
        --capabilities CAPABILITY_NAMED_IAM
        --no-fail-on-empty-changeset
        --tags
            "Project=$PROJECT_NAME"
            "Environment=$ENV"
            "ManagedBy=cloudformation"
    )

    if [[ -n "$params" && -f "$PROJECT_DIR/parameters/$params" ]]; then
        cmd+=(--parameter-overrides "file://$PROJECT_DIR/parameters/$params")
    fi

    "${cmd[@]}"
    log_info "Stack $stack_name deployed successfully."
}

deploy_network() {
    deploy_stack \
        "${PROJECT_NAME}-network-${ENV}" \
        "network.yaml" \
        "${ENV}.json"
}

deploy_event_driven() {
    deploy_stack \
        "${PROJECT_NAME}-events-${ENV}" \
        "event-driven.yaml" \
        ""
}

# -------------------------------------------------------------------
# Main
# -------------------------------------------------------------------
validate_env
confirm_production
check_prerequisites
lint_templates

case "$STACK" in
    network)
        deploy_network
        ;;
    events|event-driven)
        deploy_event_driven
        ;;
    all)
        deploy_network
        deploy_event_driven
        ;;
    *)
        log_error "Unknown stack: $STACK (must be network|events|all)"
        exit 1
        ;;
esac

echo ""
log_info "Deployment complete for $ENV ($STACK)."
log_info "Check status: aws cloudformation describe-stacks --stack-name ${PROJECT_NAME}-network-${ENV} --region $REGION --query 'Stacks[0].StackStatus'"
