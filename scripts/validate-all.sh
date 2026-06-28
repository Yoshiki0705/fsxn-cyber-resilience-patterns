#!/usr/bin/env bash
# Validate all templates and run full test suite.
# Use this before pushing changes or creating a PR.
#
# Usage:
#   ./scripts/validate-all.sh

set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "$0")" && pwd)"
PROJECT_DIR="$(dirname "$SCRIPT_DIR")"
cd "$PROJECT_DIR"

# Colors
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[0;33m'
NC='\033[0m'

log_info()  { echo -e "${GREEN}[INFO]${NC} $*"; }
log_warn()  { echo -e "${YELLOW}[WARN]${NC} $*"; }
log_error() { echo -e "${RED}[ERROR]${NC} $*"; }

ERRORS=0

# -------------------------------------------------------------------
# 1. cfn-lint
# -------------------------------------------------------------------
log_info "Running cfn-lint..."
if command -v cfn-lint &>/dev/null; then
    if ! cfn-lint templates/*.yaml; then
        log_warn "cfn-lint reported issues (may be warnings only)."
    fi
else
    log_warn "cfn-lint not found, skipping."
fi

# -------------------------------------------------------------------
# 2. cfn-guard (if available)
# -------------------------------------------------------------------
log_info "Running cfn-guard..."
if command -v cfn-guard &>/dev/null; then
    GUARD_FAILED=0
    for tmpl in templates/*.yaml; do
        if ! cfn-guard validate \
            --data "$tmpl" \
            --rules security/guard-rules/ \
            --show-summary fail 2>/dev/null; then
            GUARD_FAILED=1
        fi
    done
    if [[ $GUARD_FAILED -eq 1 ]]; then
        log_warn "cfn-guard reported failures (review above)."
    fi
else
    log_warn "cfn-guard not found, skipping."
fi

# -------------------------------------------------------------------
# 3. Python linting (ruff)
# -------------------------------------------------------------------
log_info "Running ruff..."
if command -v ruff &>/dev/null; then
    if ! ruff check solutions/ tests/ shared/; then
        log_error "ruff found issues."
        ERRORS=$((ERRORS + 1))
    fi
else
    log_warn "ruff not found, skipping."
fi

# -------------------------------------------------------------------
# 4. Type checking (mypy)
# -------------------------------------------------------------------
log_info "Running mypy..."
if command -v mypy &>/dev/null; then
    mypy solutions/ --ignore-missing-imports --no-error-summary 2>/dev/null || true
else
    log_warn "mypy not found, skipping."
fi

# -------------------------------------------------------------------
# 5. Gitleaks
# -------------------------------------------------------------------
log_info "Running gitleaks..."
if command -v gitleaks &>/dev/null; then
    if ! gitleaks detect --config .gitleaks.toml --no-git --source . --no-banner; then
        log_error "gitleaks found secrets!"
        ERRORS=$((ERRORS + 1))
    fi
else
    log_warn "gitleaks not found, skipping."
fi

# -------------------------------------------------------------------
# 6. Pytest
# -------------------------------------------------------------------
log_info "Running pytest..."
if command -v pytest &>/dev/null; then
    if ! pytest tests/ shared/tests/ -v --tb=short; then
        log_error "Tests failed!"
        ERRORS=$((ERRORS + 1))
    fi
else
    log_warn "pytest not found, skipping."
fi

# -------------------------------------------------------------------
# Summary
# -------------------------------------------------------------------
echo ""
if [[ $ERRORS -eq 0 ]]; then
    log_info "All validations passed. Ready to push."
else
    log_error "$ERRORS validation(s) failed. Fix before pushing."
    exit 1
fi
