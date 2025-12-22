#!/bin/bash

# Server Monitoring Agent Update Script
# This script updates the agent to the latest version from GitHub

set -e  # Exit on any error

# Detect agent directory (works for both standalone and submodule)
SCRIPT_DIR="$( cd "$( dirname "${BASH_SOURCE[0]}" )" && pwd )"
AGENT_DIR="$SCRIPT_DIR"
LOG_FILE="$AGENT_DIR/update.log"

# Function to log to both file and stdout
log() {
  echo "$1" | tee -a "$LOG_FILE"
}

log "============================================="
log "Update started at $(date)"
log "============================================="

cd "$AGENT_DIR"

# Stash any local changes
log "Stashing local changes..."
git stash push -m "Auto-stash before update" 2>&1 | tee -a "$LOG_FILE" || true

# Pull latest changes
log "Pulling latest changes from GitHub..."
git pull origin main 2>&1 | tee -a "$LOG_FILE"

# Restore stashed changes (keep .env, discard rest)
log "Restoring local .env if needed..."
if git stash list | grep -q "Auto-stash before update"; then
  git checkout stash@{0} -- .env 2>&1 | tee -a "$LOG_FILE" || true
  git stash drop 2>&1 | tee -a "$LOG_FILE" || true
fi

# Install dependencies
log "Installing dependencies..."
npm install 2>&1 | tee -a "$LOG_FILE"

# Build TypeScript
log "Building TypeScript..."
npm run build 2>&1 | tee -a "$LOG_FILE"

# Restart PM2 process
log "Restarting agent..."
pm2 restart monitor-agent 2>&1 | tee -a "$LOG_FILE"

log "✅ Update completed successfully at $(date)"
log "============================================="
log ""

exit 0
