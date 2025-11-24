#!/bin/bash
# =============================================================================
# Pre-commit Hook: Secrets Detection (SCRUM-26)
# =============================================================================
# This script prevents accidental commits of sensitive data.
# Install: cp scripts/pre-commit-secrets-check.sh .git/hooks/pre-commit && chmod +x .git/hooks/pre-commit
#
# Author: Seth Valentine (initial implementation)
# Enhanced: Claude Code

set -e

echo "Running secrets detection check..."

# Colors for output
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
NC='\033[0m' # No Color

# Files to always block
BLOCKED_FILES=(
    ".env"
    ".env.production"
    ".env.staging"
    ".env.local"
    "credentials.json"
    "service-account.json"
    "secrets.yaml"
    "secrets.yml"
)

# Patterns that indicate secrets (regex)
SECRET_PATTERNS=(
    "password\s*=\s*['\"][^'\"]+['\"]"
    "api_key\s*=\s*['\"][^'\"]+['\"]"
    "secret_key\s*=\s*['\"][^'\"]+['\"]"
    "AWS_SECRET_ACCESS_KEY\s*=\s*[^$]"
    "PRIVATE_KEY"
    "-----BEGIN RSA PRIVATE KEY-----"
    "-----BEGIN OPENSSH PRIVATE KEY-----"
    "-----BEGIN EC PRIVATE KEY-----"
    "sk_live_"
    "pk_live_"
    "ghp_[a-zA-Z0-9]{36}"
    "xox[baprs]-[0-9a-zA-Z]+"
)

BLOCKED=0

# Check for blocked files
echo "Checking for blocked files..."
for file in "${BLOCKED_FILES[@]}"; do
    if git diff --cached --name-only | grep -q "^${file}$"; then
        echo -e "${RED}ERROR: Attempting to commit blocked file: ${file}${NC}"
        BLOCKED=1
    fi
done

# Check staged files for secret patterns
echo "Scanning for secret patterns..."
for pattern in "${SECRET_PATTERNS[@]}"; do
    # Get list of staged files (excluding .secret and binary files)
    STAGED_FILES=$(git diff --cached --name-only --diff-filter=ACM | grep -v '\.secret$' | grep -v '\.png$' | grep -v '\.jpg$' | grep -v '\.pdf$' || true)

    for file in $STAGED_FILES; do
        if [ -f "$file" ]; then
            # Check if file contains the pattern
            if git diff --cached "$file" | grep -iE "$pattern" > /dev/null 2>&1; then
                echo -e "${YELLOW}WARNING: Potential secret found in ${file}${NC}"
                echo -e "${YELLOW}Pattern matched: ${pattern}${NC}"
                # Don't block, just warn - some patterns might be false positives
            fi
        fi
    done
done

# Check for high-entropy strings (potential API keys/tokens)
echo "Checking for high-entropy strings..."
STAGED_FILES=$(git diff --cached --name-only --diff-filter=ACM | grep -E '\.(py|js|ts|json|yaml|yml|env)$' || true)
for file in $STAGED_FILES; do
    if [ -f "$file" ]; then
        # Look for long alphanumeric strings that might be tokens (40+ chars)
        if git diff --cached "$file" | grep -oE '[A-Za-z0-9_-]{40,}' | head -1 > /dev/null 2>&1; then
            MATCH=$(git diff --cached "$file" | grep -oE '[A-Za-z0-9_-]{40,}' | head -1)
            if [ -n "$MATCH" ]; then
                echo -e "${YELLOW}WARNING: Long token-like string found in ${file}${NC}"
            fi
        fi
    fi
done

if [ $BLOCKED -eq 1 ]; then
    echo -e "${RED}"
    echo "=============================================="
    echo "COMMIT BLOCKED: Sensitive files detected!"
    echo "=============================================="
    echo -e "${NC}"
    echo "To proceed, remove the blocked files from staging:"
    echo "  git reset HEAD <file>"
    echo ""
    echo "If you need to commit encrypted versions, use:"
    echo "  git-secret hide"
    echo "  git add *.secret"
    exit 1
fi

echo -e "${GREEN}Secrets check passed!${NC}"
exit 0
