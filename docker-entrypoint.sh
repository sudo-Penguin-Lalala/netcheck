#!/bin/sh
set -e

# Ensure cache directory exists and is owned by netcheck user
# This runs as root, then drops privileges before exec'ing uvicorn
CACHE_DIR="${CACHE_DIR:-/data/netcheck-cache}"

# Verify netcheck user exists
if ! id netcheck >/dev/null 2>&1; then
    echo "ERROR: netcheck user does not exist" >&2
    exit 1
fi

# Create cache directory with error handling
if [ ! -d "$CACHE_DIR" ]; then
    echo "Creating cache directory: $CACHE_DIR"
    mkdir -p "$CACHE_DIR" || {
        echo "ERROR: Failed to create cache directory: $CACHE_DIR" >&2
        exit 1
    }
fi

# Set ownership with error handling
echo "Setting cache directory ownership..."
chown -R netcheck:netcheck "$CACHE_DIR" || {
    echo "ERROR: Failed to set cache directory ownership" >&2
    exit 1
}

# Verify gosu is available
if ! command -v gosu >/dev/null 2>&1; then
    echo "ERROR: gosu command not found" >&2
    exit 1
fi

# Drop privileges and exec the CMD as the netcheck user
echo "Starting NetCheck as netcheck user..."
exec gosu netcheck "$@"
