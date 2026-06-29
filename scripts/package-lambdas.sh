#!/usr/bin/env bash
# Package Lambda functions into deployment zip archives.
#
# Each Lambda is bundled with its source code and shared dependencies,
# then optionally uploaded to an S3 bucket for CloudFormation deployment.
#
# Usage:
#   ./scripts/package-lambdas.sh                    # Package only (local zips)
#   ./scripts/package-lambdas.sh --upload           # Package + upload to S3
#   ./scripts/package-lambdas.sh --bucket my-bucket # Specify S3 bucket
#   ./scripts/package-lambdas.sh --help
#
# Prerequisites:
#   - zip command available
#   - AWS CLI configured (for --upload mode)
#   - S3 bucket must have:
#     * Server-Side Encryption (SSE-S3 or SSE-KMS) enabled
#     * Bucket Policy restricting s3:GetObject to Lambda execution roles
#     * Versioning enabled (recommended for rollback)

set -euo pipefail

# -------------------------------------------------------------------
# Configuration
# -------------------------------------------------------------------
SCRIPT_DIR="$(cd "$(dirname "$0")" && pwd)"
PROJECT_DIR="$(dirname "$SCRIPT_DIR")"
OUTPUT_DIR="${PROJECT_DIR}/lambda-packages"
SHARED_DIR="${PROJECT_DIR}/solutions/shared"

# Defaults
S3_BUCKET="${LAMBDA_ARTIFACT_BUCKET:-}"
S3_PREFIX="${LAMBDA_ARTIFACT_PREFIX:-lambda-packages}"
UPLOAD=false
REGION="${AWS_REGION:-ap-northeast-1}"

# Colors
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[0;33m'
CYAN='\033[0;36m'
NC='\033[0m'

# -------------------------------------------------------------------
# Functions
# -------------------------------------------------------------------
log_info()  { echo -e "${GREEN}[INFO]${NC} $*" >&2; }
log_warn()  { echo -e "${YELLOW}[WARN]${NC} $*" >&2; }
log_error() { echo -e "${RED}[ERROR]${NC} $*" >&2; }
log_step()  { echo -e "${CYAN}[PACK]${NC} $*" >&2; }

show_help() {
    echo "Usage: $0 [OPTIONS]"
    echo ""
    echo "Package Lambda functions into deployment zip archives."
    echo ""
    echo "Options:"
    echo "  --upload          Upload packages to S3 after creation"
    echo "  --bucket NAME     S3 bucket name (or set LAMBDA_ARTIFACT_BUCKET env)"
    echo "  --prefix PREFIX   S3 key prefix (default: lambda-packages)"
    echo "  --region REGION   AWS region (default: ap-northeast-1)"
    echo "  --help            Show this help"
    echo ""
    echo "Output: lambda-packages/*.zip (local directory)"
    echo ""
    echo "S3 Bucket Requirements:"
    echo "  - Server-Side Encryption (SSE-S3 or SSE-KMS) enabled"
    echo "  - Bucket Policy: Lambda execution roles only for s3:GetObject"
    echo "  - Versioning enabled (recommended)"
}

parse_args() {
    while [[ $# -gt 0 ]]; do
        case "$1" in
            --upload)   UPLOAD=true; shift ;;
            --bucket)   S3_BUCKET="$2"; shift 2 ;;
            --prefix)   S3_PREFIX="$2"; shift 2 ;;
            --region)   REGION="$2"; shift 2 ;;
            --help|-h)  show_help; exit 0 ;;
            *)          log_error "Unknown option: $1"; show_help; exit 1 ;;
        esac
    done

    if [[ "$UPLOAD" == "true" && -z "$S3_BUCKET" ]]; then
        log_error "S3 bucket required for upload. Use --bucket or set LAMBDA_ARTIFACT_BUCKET."
        exit 1
    fi
}

compute_hash() {
    # Compute SHA256 of a directory's content (deterministic, path-independent)
    local dir="$1"
    # Hash only file contents (not paths) for reproducibility
    find "$dir" -type f | sort | while read -r f; do
        shasum -a 256 "$f"
    done | awk '{print $1}' | shasum -a 256 | cut -c1-12
}

package_one() {
    local name="$1"
    local source_dir="$2"
    local handler_file="$3"
    local needs_shared="$4"

    log_step "Packaging: ${name}"

    # Create temp build directory
    local build_dir
    build_dir=$(mktemp -d)

    # Copy handler file
    cp "${PROJECT_DIR}/${source_dir}/${handler_file}" "${build_dir}/"

    # Copy __init__.py if exists
    if [[ -f "${PROJECT_DIR}/${source_dir}/__init__.py" ]]; then
        cp "${PROJECT_DIR}/${source_dir}/__init__.py" "${build_dir}/"
    fi

    # Include shared/ if needed
    if [[ "$needs_shared" == "true" ]]; then
        cp "${SHARED_DIR}/ontap_client.py" "${build_dir}/"
    fi

    # Compute content hash
    local content_hash
    content_hash=$(compute_hash "$build_dir")
    local zip_name="${name}-${content_hash}.zip"
    local zip_path="${OUTPUT_DIR}/${zip_name}"

    # Skip if zip already exists with same hash
    if [[ -f "$zip_path" ]]; then
        log_info "  ↳ Unchanged (hash: ${content_hash}), skipping"
        rm -rf "$build_dir"
        echo "$zip_name"
        return 0
    fi

    # Remove old zips for this function
    rm -f "${OUTPUT_DIR}/${name}-"*.zip

    # Create zip
    (cd "$build_dir" && zip -q -r "$zip_path" .)

    local size
    size=$(du -h "$zip_path" | cut -f1)
    log_info "  ↳ Created: ${zip_name} (${size})"

    # Cleanup
    rm -rf "$build_dir"
    echo "$zip_name"
}

upload_to_s3() {
    local zip_name="$1"
    local zip_path="${OUTPUT_DIR}/${zip_name}"
    local s3_key="${S3_PREFIX}/${zip_name}"

    # Check if same object already exists in S3
    if aws s3api head-object \
        --bucket "$S3_BUCKET" \
        --key "$s3_key" \
        --region "$REGION" &>/dev/null; then
        log_info "  ↳ Already in S3: s3://${S3_BUCKET}/${s3_key}"
        return 0
    fi

    log_info "  ↳ Uploading to s3://${S3_BUCKET}/${s3_key}"
    aws s3 cp "$zip_path" "s3://${S3_BUCKET}/${s3_key}" \
        --region "$REGION" \
        --quiet
}

validate_zip() {
    local zip_path="$1"
    local handler_file="$2"

    if ! unzip -t "$zip_path" >/dev/null 2>&1; then
        log_error "Invalid zip: ${zip_path}"
        return 1
    fi

    # Verify handler file exists in zip (using zipinfo for reliable output)
    if ! zipinfo -1 "$zip_path" 2>/dev/null | grep -qx "$handler_file"; then
        log_error "Handler file '${handler_file}' not found in zip: ${zip_path}"
        return 1
    fi
}

# -------------------------------------------------------------------
# Main
# -------------------------------------------------------------------
parse_args "$@"

# Create output directory
mkdir -p "$OUTPUT_DIR"

log_info "Lambda Packaging — 4 functions"
log_info "Output: ${OUTPUT_DIR}/"
[[ "$UPLOAD" == "true" ]] && log_info "Upload: s3://${S3_BUCKET}/${S3_PREFIX}/"
echo "" >&2

ERRORS=0
MANIFEST_ENTRIES=""

# --- Package each Lambda ---

# 1. Event Transformer
zip_name=$(package_one "event-transformer" "solutions/event-driven-response/lambda" "event_transformer.py" "false") || { ERRORS=$((ERRORS + 1)); zip_name=""; }
if [[ -n "$zip_name" ]]; then
    validate_zip "${OUTPUT_DIR}/${zip_name}" "event_transformer.py" || ERRORS=$((ERRORS + 1))
    [[ "$UPLOAD" == "true" ]] && { upload_to_s3 "$zip_name" || ERRORS=$((ERRORS + 1)); }
    MANIFEST_ENTRIES="${MANIFEST_ENTRIES}  \"event-transformer\": \"${zip_name}\""
fi

# 2. Quarantine Action (needs shared/ontap_client.py)
zip_name=$(package_one "quarantine-action" "solutions/event-driven-response/lambda" "quarantine_action.py" "true") || { ERRORS=$((ERRORS + 1)); zip_name=""; }
if [[ -n "$zip_name" ]]; then
    validate_zip "${OUTPUT_DIR}/${zip_name}" "quarantine_action.py" || ERRORS=$((ERRORS + 1))
    [[ "$UPLOAD" == "true" ]] && { upload_to_s3 "$zip_name" || ERRORS=$((ERRORS + 1)); }
    [[ -n "$MANIFEST_ENTRIES" ]] && MANIFEST_ENTRIES="${MANIFEST_ENTRIES},"$'\n'
    MANIFEST_ENTRIES="${MANIFEST_ENTRIES}  \"quarantine-action\": \"${zip_name}\""
fi

# 3. Verdict Handler (Deep Instinct)
zip_name=$(package_one "verdict-handler" "solutions/deep-instinct" "verdict_handler.py" "false") || { ERRORS=$((ERRORS + 1)); zip_name=""; }
if [[ -n "$zip_name" ]]; then
    validate_zip "${OUTPUT_DIR}/${zip_name}" "verdict_handler.py" || ERRORS=$((ERRORS + 1))
    [[ "$UPLOAD" == "true" ]] && { upload_to_s3 "$zip_name" || ERRORS=$((ERRORS + 1)); }
    [[ -n "$MANIFEST_ENTRIES" ]] && MANIFEST_ENTRIES="${MANIFEST_ENTRIES},"$'\n'
    MANIFEST_ENTRIES="${MANIFEST_ENTRIES}  \"verdict-handler\": \"${zip_name}\""
fi

# 4. Scan Result Handler (TrendAI)
zip_name=$(package_one "scan-result-handler" "solutions/trendai-file-security" "scan_result_handler.py" "false") || { ERRORS=$((ERRORS + 1)); zip_name=""; }
if [[ -n "$zip_name" ]]; then
    validate_zip "${OUTPUT_DIR}/${zip_name}" "scan_result_handler.py" || ERRORS=$((ERRORS + 1))
    [[ "$UPLOAD" == "true" ]] && { upload_to_s3 "$zip_name" || ERRORS=$((ERRORS + 1)); }
    [[ -n "$MANIFEST_ENTRIES" ]] && MANIFEST_ENTRIES="${MANIFEST_ENTRIES},"$'\n'
    MANIFEST_ENTRIES="${MANIFEST_ENTRIES}  \"scan-result-handler\": \"${zip_name}\""
fi

# --- Summary ---
echo "" >&2
if [[ $ERRORS -eq 0 ]]; then
    log_info "All 4 Lambda packages created successfully."
else
    log_error "${ERRORS} error(s) during packaging."
    exit 1
fi

# Write manifest
MANIFEST="${OUTPUT_DIR}/manifest.json"
printf '{\n%s\n}\n' "$MANIFEST_ENTRIES" > "$MANIFEST"
log_info "Manifest: ${MANIFEST}"
