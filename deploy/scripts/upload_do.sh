#!/bin/bash
# Upload DNS health results to DigitalOcean Spaces
#
# Usage:
#   ./scripts/upload_do.sh <file1> [file2] [file3] ...
#
# Requires:
#   - s3cmd or aws cli configured
#   - DO_SPACES_KEY, DO_SPACES_SECRET, DO_BUCKET, DO_SPACES_REGION in config.env

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
if [[ -z "${DO_SPACES_KEY:-}" ]] || [[ -z "${DO_SPACES_SECRET:-}" ]]; then
    echo "Error: DO_SPACES_KEY and DO_SPACES_SECRET must be set"
    exit 1
fi

DO_BUCKET="${DO_BUCKET:-exitmap-dns-results}"
DO_SPACES_REGION="${DO_SPACES_REGION:-nyc3}"
DO_SPACES_ENDPOINT="${DO_SPACES_ENDPOINT:-https://${DO_SPACES_REGION}.digitaloceanspaces.com}"

# Upload files
for FILE in "$@"; do
    if [[ ! -f "$FILE" ]]; then
        echo "Warning: File not found: $FILE"
        continue
    fi
    
    BASENAME=$(basename "$FILE")
    
    # Determine content type and cache settings
    CONTENT_TYPE="application/json"
    if [[ "$BASENAME" == "latest.json" ]] || [[ "$BASENAME" == "files.json" ]]; then
        # Short cache for frequently updated files
        CACHE_CONTROL="public, max-age=60"
    else
        # Long cache for immutable historical files
        CACHE_CONTROL="public, max-age=31536000, immutable"
    fi
    
    echo "Uploading $BASENAME to DO Spaces..."
    
    # Use AWS CLI if available, otherwise s3cmd
    if command -v aws &>/dev/null; then
        AWS_ACCESS_KEY_ID="$DO_SPACES_KEY" \
        AWS_SECRET_ACCESS_KEY="$DO_SPACES_SECRET" \
        aws s3 cp "$FILE" "s3://${DO_BUCKET}/${BASENAME}" \
            --endpoint-url "$DO_SPACES_ENDPOINT" \
            --content-type "$CONTENT_TYPE" \
            --cache-control "$CACHE_CONTROL" \
            --acl public-read
    elif command -v s3cmd &>/dev/null; then
        s3cmd put "$FILE" "s3://${DO_BUCKET}/${BASENAME}" \
            --host="${DO_SPACES_REGION}.digitaloceanspaces.com" \
            --host-bucket="%(bucket)s.${DO_SPACES_REGION}.digitaloceanspaces.com" \
            --access_key="$DO_SPACES_KEY" \
            --secret_key="$DO_SPACES_SECRET" \
            --mime-type="$CONTENT_TYPE" \
            --add-header="Cache-Control:${CACHE_CONTROL}" \
            --acl-public
    else
        echo "Error: Neither aws cli nor s3cmd found. Install one of them."
        exit 1
    fi
    
    echo "Uploaded: $BASENAME"
done

echo "DO Spaces upload complete"
