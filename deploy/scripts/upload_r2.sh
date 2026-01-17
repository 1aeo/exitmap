#!/bin/bash
# Upload DNS health results to Cloudflare R2
#
# Usage:
#   ./scripts/upload_r2.sh <file1> [file2] [file3] ...
#
# Requires:
#   - aws cli (R2 is S3-compatible)
#   - R2_ACCESS_KEY_ID, R2_SECRET_ACCESS_KEY, R2_BUCKET, R2_ENDPOINT in config.env

set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
DEPLOY_DIR="$(dirname "$SCRIPT_DIR")"
EXITMAP_DIR="$(dirname "$DEPLOY_DIR")"

# Load configuration
if [[ -f "$DEPLOY_DIR/config.env" ]]; then
    source "$DEPLOY_DIR/config.env"
elif [[ -f "$EXITMAP_DIR/config.env" ]]; then
    source "$EXITMAP_DIR/config.env"
fi

# Check required variables
if [[ -z "${R2_ACCESS_KEY_ID:-}" ]] || [[ -z "${R2_SECRET_ACCESS_KEY:-}" ]]; then
    echo "Error: R2_ACCESS_KEY_ID and R2_SECRET_ACCESS_KEY must be set"
    exit 1
fi

if [[ -z "${R2_ENDPOINT:-}" ]]; then
    echo "Error: R2_ENDPOINT must be set (e.g., https://<account_id>.r2.cloudflarestorage.com)"
    exit 1
fi

R2_BUCKET="${R2_BUCKET:-exitmap-dns-results}"

# Upload files
for FILE in "$@"; do
    if [[ ! -f "$FILE" ]]; then
        echo "Warning: File not found: $FILE"
        continue
    fi
    
    BASENAME=$(basename "$FILE")
    
    # Determine content type
    CONTENT_TYPE="application/json"
    
    echo "Uploading $BASENAME to R2..."
    
    AWS_ACCESS_KEY_ID="$R2_ACCESS_KEY_ID" \
    AWS_SECRET_ACCESS_KEY="$R2_SECRET_ACCESS_KEY" \
    aws s3 cp "$FILE" "s3://${R2_BUCKET}/${BASENAME}" \
        --endpoint-url "$R2_ENDPOINT" \
        --content-type "$CONTENT_TYPE"
    
    echo "Uploaded: $BASENAME"
done

# Purge Cloudflare cache if configured
if [[ -n "${CF_API_TOKEN:-}" ]] && [[ -n "${CF_ACCOUNT_ID:-}" ]] && [[ -n "${PAGES_PROJECT:-}" ]]; then
    echo "Purging Cloudflare Pages cache..."
    
    # Get the pages domain
    PAGES_DOMAIN="${PAGES_PROJECT}.pages.dev"
    
    # Purge specific URLs
    URLS_TO_PURGE=""
    for FILE in "$@"; do
        BASENAME=$(basename "$FILE")
        URLS_TO_PURGE="${URLS_TO_PURGE}\"https://${PAGES_DOMAIN}/${BASENAME}\","
    done
    URLS_TO_PURGE="${URLS_TO_PURGE%,}"  # Remove trailing comma
    
    curl -s -X POST "https://api.cloudflare.com/client/v4/zones/${CF_ACCOUNT_ID}/purge_cache" \
        -H "Authorization: Bearer ${CF_API_TOKEN}" \
        -H "Content-Type: application/json" \
        --data "{\"files\":[${URLS_TO_PURGE}]}" \
        > /dev/null 2>&1 || echo "Cache purge failed (non-critical)"
fi

echo "R2 upload complete"
