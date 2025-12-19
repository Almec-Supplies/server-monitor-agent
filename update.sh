#!/bin/bash

# Server Monitoring Agent Update Script
# This script updates the agent to the latest version from GitHub

set -e  # Exit on any error

AGENT_DIR="/opt/monitoring-agent"
LOG_FILE="$AGENT_DIR/update.log"

echo "=============================================" >> "$LOG_FILE"
echo "Update started at $(date)" >> "$LOG_FILE"
echo "=============================================" >> "$LOG_FILE"

cd "$AGENT_DIR"

# Stash any local changes to .env
echo "Stashing local changes..." >> "$LOG_FILE"
git stash push -m "Auto-stash before update" .env 2>> "$LOG_FILE" || true

# Pull latest changes
echo "Pulling latest changes from GitHub..." >> "$LOG_FILE"
git pull origin main >> "$LOG_FILE" 2>&1

# Restore .env if it was stashed
echo "Restoring local .env..." >> "$LOG_FILE"
git stash pop 2>> "$LOG_FILE" || true

# Install dependencies
echo "Installing dependencies..." >> "$LOG_FILE"
npm install >> "$LOG_FILE" 2>&1

# Build TypeScript
echo "Building TypeScript..." >> "$LOG_FILE"
npm run build >> "$LOG_FILE" 2>&1

# Restart PM2 process
echo "Restarting agent..." >> "$LOG_FILE"
pm2 restart monitor-agent >> "$LOG_FILE" 2>&1

echo "✅ Update completed successfully at $(date)" >> "$LOG_FILE"
echo "=============================================" >> "$LOG_FILE"
echo "" >> "$LOG_FILE"

exit 0
