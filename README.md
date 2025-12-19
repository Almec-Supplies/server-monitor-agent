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

7. Verify it's running:
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

- Linux-based operating system
- Node.js 18 or higher
- Network access to monitoring API server
- Permissions to read system metrics (runs as regular user)

## License

MIT
