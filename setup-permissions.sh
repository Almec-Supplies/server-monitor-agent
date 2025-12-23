#!/bin/bash

# Server Monitoring Agent - Setup Script
# This script configures the necessary permissions for the monitoring agent

set -e

USER="${1:-$USER}"
COLOR_GREEN='\033[0;32m'
COLOR_YELLOW='\033[1;33m'
COLOR_RED='\033[0;31m'
COLOR_RESET='\033[0m'

echo -e "${COLOR_GREEN}=== Server Monitoring Agent - Setup ===${COLOR_RESET}"
echo ""

# Check if running as root
if [ "$EUID" -eq 0 ]; then 
  echo -e "${COLOR_RED}Error: Do not run this script as root${COLOR_RESET}"
  echo "Run as regular user: ./setup-permissions.sh"
  exit 1
fi

echo -e "${COLOR_YELLOW}This script will:${COLOR_RESET}"
echo "1. Add user '$USER' to the 'adm' group"
echo "2. Configure passwordless sudo for monitoring commands"
echo ""
read -p "Continue? (y/n) " -n 1 -r
echo
if [[ ! $REPLY =~ ^[Yy]$ ]]; then
  echo "Setup cancelled."
  exit 1
fi

echo ""
echo -e "${COLOR_GREEN}Step 1: Adding user to adm group...${COLOR_RESET}"
sudo usermod -aG adm $USER

echo -e "${COLOR_GREEN}Step 2: Creating sudoers configuration...${COLOR_RESET}"
SUDOERS_FILE="/etc/sudoers.d/monitoring-agent"
sudo tee $SUDOERS_FILE > /dev/null <<EOF
# Monitoring Agent - Passwordless sudo for specific commands
# Created by setup-permissions.sh on $(date)

# Log file access
$USER ALL=(ALL) NOPASSWD: /usr/bin/find /var/log/nginx -name *.error.log -type f
$USER ALL=(ALL) NOPASSWD: /usr/bin/find /var/www/vhosts/system -name error_log -type f
$USER ALL=(ALL) NOPASSWD: /usr/bin/find /var/www/vhosts/system -maxdepth 2 -name nginx.conf
$USER ALL=(ALL) NOPASSWD: /usr/bin/tail /var/log/*
$USER ALL=(ALL) NOPASSWD: /usr/bin/tail /var/www/vhosts/system/*/*
$USER ALL=(ALL) NOPASSWD: /usr/bin/grep * /var/log/auth.log

# File testing
$USER ALL=(ALL) NOPASSWD: /usr/bin/test

# Firewall status
$USER ALL=(ALL) NOPASSWD: /usr/sbin/ufw status
$USER ALL=(ALL) NOPASSWD: /usr/sbin/iptables -L -n
$USER ALL=(ALL) NOPASSWD: /usr/sbin/firewall --status

# Fail2ban monitoring
$USER ALL=(ALL) NOPASSWD: /usr/bin/systemctl is-active fail2ban
$USER ALL=(ALL) NOPASSWD: /usr/bin/fail2ban-client *

# User directory checks
$USER ALL=(ALL) NOPASSWD: /usr/bin/find /home -maxdepth 1 -type d -mtime -30 -printf *
EOF

# Set proper permissions
sudo chmod 0440 $SUDOERS_FILE

# Verify sudoers syntax
if sudo visudo -c -f $SUDOERS_FILE; then
  echo -e "${COLOR_GREEN}✓ Sudoers configuration created successfully${COLOR_RESET}"
else
  echo -e "${COLOR_RED}✗ Error in sudoers configuration${COLOR_RESET}"
  sudo rm $SUDOERS_FILE
  exit 1
fi

echo ""
echo -e "${COLOR_GREEN}=== Setup Complete ===${COLOR_RESET}"
echo ""
echo -e "${COLOR_YELLOW}Important: You must log out and log back in for group changes to take effect${COLOR_RESET}"
echo ""
echo "After logging back in, verify with:"
echo "  groups | grep adm"
echo "  sudo -l | grep NOPASSWD"
echo ""
echo "Then you can start the agent with:"
echo "  pm2 start dist/index.js --name monitor-agent"
echo ""
