# Server Monitoring Agent

Lightweight monitoring agent that collects system metrics, process information, and security audits from your servers.

## Features

- **System Metrics**: CPU, memory, disk usage, network traffic
- **Process Monitoring**: Automatic tracking of top memory consumers + configurable process list
- **Security Audits**: Firewall status, open ports, failed logins, SSH configuration
- **Lightweight**: ~70MB RAM usage
- **Auto-restart**: Runs via PM2 with automatic recovery

## Installation

### Prerequisites
- Node.js 18+
- User account with appropriate permissions (see System Requirements below)

### System Requirements

The monitoring agent needs access to system logs and commands. You have two options:

#### Option A: Automated Setup (Recommended)

Run the included setup script:
```bash
cd /opt/monitoring-agent
./setup-permissions.sh
```

This will automatically:
- Add your user to the `adm` group
- Create `/etc/sudoers.d/monitoring-agent` with required permissions
- Verify the configuration

**Important:** Log out and log back in after running the script for group changes to take effect.

#### Option B: Manual Setup

1. **Add user to the `adm` group** (for log file access):
```bash
sudo usermod -aG adm $USER
```

2. **Configure passwordless sudo** for specific commands:
```bash
sudo visudo -f /etc/sudoers.d/monitoring-agent
```

Add the following lines (replace `username` with your actual username):
```
# Monitoring Agent - Passwordless sudo for specific commands
username ALL=(ALL) NOPASSWD: /usr/bin/find /var/log/nginx -name *.error.log -type f
username ALL=(ALL) NOPASSWD: /usr/bin/tail /var/log/*
username ALL=(ALL) NOPASSWD: /usr/bin/test
username ALL=(ALL) NOPASSWD: /usr/bin/grep * /var/log/auth.log
username ALL=(ALL) NOPASSWD: /usr/sbin/ufw status
username ALL=(ALL) NOPASSWD: /usr/sbin/iptables -L -n
username ALL=(ALL) NOPASSWD: /usr/bin/systemctl is-active fail2ban
username ALL=(ALL) NOPASSWD: /usr/bin/fail2ban-client *
username ALL=(ALL) NOPASSWD: /usr/bin/find /home -maxdepth 1 -type d -mtime -30 -printf *
```

Save and exit (Ctrl+X, Y, Enter).

3. **Log out and log back in** for group changes to take effect:
```bash
# Verify you're in the adm group
groups
# Should show: username ... adm ...
```

### Quick Start

1. Install PM2 globally (if not already installed):
```bash
sudo npm install -g pm2
```

2. Clone the repository and set ownership:
```bash
sudo git clone https://github.com/Almec-Supplies/server-monitor-agent.git /opt/monitoring-agent
sudo chown -R $USER:$USER /opt/monitoring-agent
cd /opt/monitoring-agent
```

3. Install dependencies:
```bash
npm install
```

4. Build the TypeScript code:
```bash
npm run build
```

5. Create `.env` file with your configuration:

Create a `.env` file in the project root with the following content:
```bash
API_URL=your-monitoring-api-url
API_KEY=your-api-key-from-administrator
SERVER_NAME="Your Server Name"
INTERVAL_SECONDS=30
MONITORED_PROCESSES=nginx,postgresql,node
```

Contact your system administrator to obtain the API URL and API key.

6. Start the agent with PM2:
```bash
pm2 start dist/index.js --name monitor-agent
pm2 save
pm2 startup  # Follow instructions to enable auto-start on boot
```

### Verification

After installation, verify your setup:

1. **Check user is in adm group:**
```bash
groups | grep adm
```

2. **Test sudo access (should not ask for password):**
```bash
sudo tail -1 /var/log/auth.log
sudo ufw status
```

3. **Check agent logs:**
```bash
pm2 logs monitor-agent --lines 20
```

You should see output like:
```
📊 Collecting metrics from Your Server Name...
   CPU: 5.2%
   Memory: 45.3%
   Disk: 12.0%
✅ Metrics sent successfully
```

Your server should appear in the monitoring dashboard with a green indicator within 30 seconds.

## Configuration

All configuration is done via the `.env` file:

- `API_URL`: URL of your monitoring API server
- `API_KEY`: Unique API key for this server (obtain from administrator)
- `SERVER_NAME`: Display name for this server
- `INTERVAL_SECONDS`: Collection interval (default: 30)
- `MONITORED_PROCESSES`: Comma-separated list of specific processes to track

## What's Collected

### Metrics (every 30s)
- CPU usage and load averages
- Memory usage (total, used, free)
- Disk usage
- Network traffic (bytes sent/received)
- System uptime

### Processes (every 30s)
- Top 10 processes by memory usage
- Configured processes from MONITORED_PROCESSES
- CPU and memory per process
- Process status

### Security Audits (every 5 minutes)
- Firewall status (ufw)
- Open network ports
- Recent failed login attempts
- SSH configuration security

## Troubleshooting

**Agent not collecting metrics:**
- Verify user is in `adm` group: `groups`
- Check sudo permissions: `sudo -l`
- Ensure you logged out/in after group change

**Permission denied errors:**
- Check `/etc/sudoers.d/monitoring-agent` exists and has correct username
- Verify log files are readable: `ls -la /var/log/auth.log`

**Check if agent is running:**
```bash
pm2 list
```

**View logs:**
```bash
pm2 logs monitor-agent
```

**Restart agent:**
```bash
pm2 restart monitor-agent
```

**Stop agent:**
```bash
pm2 stop monitor-agent
pm2 delete monitor-agent
```

## Requirements

- Linux-based operating system (Ubuntu/Debian recommended)
- Node.js 18 or higher
- Network access to monitoring API server
- User with sudo privileges for initial setup
- User in `adm` group for log access
- Passwordless sudo for specific monitoring commands (see Installation)

## Security Notes

The agent requires passwordless sudo for specific read-only commands to collect security metrics. These commands are limited to:
- Reading log files (`tail`, `grep`)
- Checking firewall status (`ufw`, `iptables`)
- Testing file existence (`test`, `find`)
- Querying fail2ban status

All sudo commands are scoped to the minimum required paths and operations. The agent runs as a regular user and does NOT have full sudo access.

## License

MIT
