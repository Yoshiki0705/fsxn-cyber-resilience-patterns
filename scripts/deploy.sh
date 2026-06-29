#!/usr/bin/env bash
# Deploy FSx for ONTAP Cyber Resilience stacks.
#
# Usage:
#   ./scripts/deploy.sh [ENV] [STACK]
#
# Examples:
#   ./scripts/deploy.sh dev                # Deploy all stacks to dev
#   ./scripts/deploy.sh dev network        # Deploy only network stack
#   ./scripts/deploy.sh dev package        # Package Lambdas only
#   ./scripts/deploy.sh production all     # Deploy all to production (confirms)

set -euo pipefail

# -------------------------------------------------------------------
# Configuration
# -------------------------------------------------------------------
if [[ "${1:-}" == "--help" || "${1:-}" == "-h" ]]; then
    echo "Usage: $0 [ENV] [STACK]"
    echo ""
    echo "  ENV    Target environment: dev | staging | production (default: dev)"
    echo "  STACK  Stack to deploy (default: all):"
    echo "           package       — Package Lambda functions only"
    echo "           network       — Network stack (VPC, subnets, SGs)"
    echo "           storage       — Storage stack (FSx for ONTAP, KMS)"
    echo "           events        — Event-driven stack (SQS, EventBridge, Step Functions)"
    echo "           scanning      — Scanning stack (EC2 scanners)"
    echo "           observability — Observability stack (Dashboard, alarms)"
    echo "           all           — All stacks in dependency order"
    echo ""
    echo "  Deploy order: package → network → storage → events → scanning → observability"
    exit 0
fi

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

wait_for_stack() {
    local stack_name="$1"
    log_info "Waiting for stack: $stack_name..."
    if ! aws cloudformation wait stack-create-complete \
        --stack-name "$stack_name" --region "$REGION" 2>/dev/null; then
        # Try update-complete if create-complete fails (stack may already exist)
        aws cloudformation wait stack-update-complete \
            --stack-name "$stack_name" --region "$REGION" 2>/dev/null || true
    fi
}

deploy_stack() {
    local stack_name="$1"
    local template="$2"
    shift 2
    local extra_params=("$@")

    log_info "Deploying stack: $stack_name ($template)"

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

    if [[ ${#extra_params[@]} -gt 0 ]]; then
        cmd+=(--parameter-overrides "${extra_params[@]}")
    fi

    if ! "${cmd[@]}"; then
        log_error "Stack deployment failed: $stack_name"
        log_error "Check: aws cloudformation describe-stack-events --stack-name $stack_name --region $REGION"
        exit 1
    fi

    log_info "Stack $stack_name deployed successfully."
}

package_lambdas() {
    log_info "Packaging Lambda functions..."
    "${SCRIPT_DIR}/package-lambdas.sh"
}

deploy_network() {
    local params_file="$PROJECT_DIR/parameters/${ENV}.json"
    if [[ -f "$params_file" ]]; then
        deploy_stack "${PROJECT_NAME}-network-${ENV}" "network.yaml" \
            "file://$params_file"
    else
        deploy_stack "${PROJECT_NAME}-network-${ENV}" "network.yaml"
    fi
}

deploy_storage() {
    deploy_stack "${PROJECT_NAME}-storage-${ENV}" "storage.yaml" \
        "ProjectName=$PROJECT_NAME" "Environment=$ENV"
}

deploy_events() {
    # Requires Lambda artifacts — check manifest exists
    local manifest="$PROJECT_DIR/lambda-packages/manifest.json"
    if [[ ! -f "$manifest" ]]; then
        log_warn "Lambda packages not found. Running package step..."
        package_lambdas
    fi

    local bucket="${LAMBDA_ARTIFACT_BUCKET:-}"
    if [[ -z "$bucket" ]]; then
        log_error "LAMBDA_ARTIFACT_BUCKET env var required for events stack deployment."
        log_error "Set it to the S3 bucket containing Lambda packages."
        exit 1
    fi

    deploy_stack "${PROJECT_NAME}-events-${ENV}" "event-driven.yaml" \
        "ProjectName=$PROJECT_NAME" \
        "Environment=$ENV" \
        "LambdaArtifactBucket=$bucket" \
        "LambdaArtifactPrefix=lambda-packages" \
        "EventTransformerS3Key=$(python3 -c "import json; print(json.load(open('$manifest'))['event-transformer'])")" \
        "QuarantineActionS3Key=$(python3 -c "import json; print(json.load(open('$manifest'))['quarantine-action'])")"
}

deploy_scanning() {
    deploy_stack "${PROJECT_NAME}-scanning-${ENV}" "scanning.yaml" \
        "ProjectName=$PROJECT_NAME" "Environment=$ENV"
}

deploy_observability() {
    local sns_arn
    sns_arn=$(aws cloudformation describe-stacks \
        --stack-name "${PROJECT_NAME}-events-${ENV}" \
        --region "$REGION" \
        --query "Stacks[0].Outputs[?OutputKey=='SecurityAlertTopicArn'].OutputValue" \
        --output text 2>/dev/null || echo "")

    if [[ -z "$sns_arn" ]]; then
        log_warn "SecurityAlertTopicArn not found (events stack may not be deployed)."
        log_warn "Deploying observability without alarm actions."
        sns_arn="arn:aws:sns:${REGION}:123456789012:placeholder"
    fi

    deploy_stack "${PROJECT_NAME}-observability-${ENV}" "observability.yaml" \
        "ProjectName=$PROJECT_NAME" "Environment=$ENV" "SecurityAlertTopicArn=$sns_arn"
}

# -------------------------------------------------------------------
# Main
# -------------------------------------------------------------------
validate_env
confirm_production

if [[ "$STACK" != "package" ]]; then
    check_prerequisites
    lint_templates
fi

case "$STACK" in
    package)
        package_lambdas
        ;;
    network)
        deploy_network
        ;;
    storage)
        deploy_storage
        ;;
    events|event-driven)
        deploy_events
        ;;
    scanning)
        deploy_scanning
        ;;
    observability)
        deploy_observability
        ;;
    all)
        package_lambdas
        deploy_network
        wait_for_stack "${PROJECT_NAME}-network-${ENV}"
        deploy_storage
        wait_for_stack "${PROJECT_NAME}-storage-${ENV}"
        deploy_events
        wait_for_stack "${PROJECT_NAME}-events-${ENV}"
        deploy_scanning
        deploy_observability
        ;;
    *)
        log_error "Unknown stack: $STACK"
        log_error "Valid: package | network | storage | events | scanning | observability | all"
        exit 1
        ;;
esac

echo ""
log_info "Deployment complete for $ENV ($STACK)."
