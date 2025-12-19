import dotenv from 'dotenv';
import { MetricsCollector } from './collectors/metrics';
import { ProcessCollector } from './collectors/processes';
import { SecurityCollector } from './collectors/security';
import { exec } from 'child_process';
import { promisify } from 'util';
import * as path from 'path';
import * as fs from 'fs';

const execAsync = promisify(exec);

dotenv.config();

const API_URL = process.env.API_URL || 'http://localhost:5000';
const API_KEY = process.env.API_KEY || 'dev-test-key-12345';
const SERVER_NAME = process.env.SERVER_NAME || 'unknown';
const INTERVAL_SECONDS = parseInt(process.env.INTERVAL_SECONDS || '30');

// Read version from package.json
const packageJsonPath = path.join(__dirname, '../package.json');
const packageJson = JSON.parse(fs.readFileSync(packageJsonPath, 'utf-8'));
const AGENT_VERSION = packageJson.version;

// Parse monitored processes from env (comma-separated)
const MONITORED_PROCESSES = process.env.MONITORED_PROCESSES
  ? process.env.MONITORED_PROCESSES.split(',').map(p => p.trim())
  : ['nginx', 'postgresql', 'node'];

class MonitoringAgent {
  private metricsCollector: MetricsCollector;
  private processCollector: ProcessCollector;
  private securityCollector: SecurityCollector;
  private intervalId?: NodeJS.Timeout;
  private securityIntervalId?: NodeJS.Timeout;

  constructor() {
    this.metricsCollector = new MetricsCollector();
    this.processCollector = new ProcessCollector({ processes: MONITORED_PROCESSES });
    this.securityCollector = new SecurityCollector();
  }

  async sendMetrics() {
    try {
      const metrics = await this.metricsCollector.collectAll();

      console.log(`📊 Collecting metrics from ${SERVER_NAME}...`);
      console.log(`   CPU: ${metrics.cpu.usage.toFixed(1)}%`);
      console.log(`   Memory: ${metrics.memory.usagePercent.toFixed(1)}%`);
      console.log(`   Disk: ${metrics.disk.usagePercent.toFixed(1)}%`);

      const response = await fetch(`${API_URL}/api/metrics`, {
        method: 'POST',
        headers: {
          'Content-Type': 'application/json',
          'X-API-Key': API_KEY,
          'X-Agent-Version': AGENT_VERSION,
        },
        body: JSON.stringify(metrics),
      });

      if (!response.ok) {
        const error = await response.text();
        console.error(`❌ Failed to send metrics: ${response.status} - ${error}`);
        return;
      }

      const result = (await response.json()) as { id: number; timestamp: string; update_required?: boolean; target_version?: string };
      console.log(`✅ Metrics sent successfully (ID: ${result.id})\n`);

      // Check if update is required
      if (result.update_required && result.target_version) {
        console.log(`🔄 Update requested to version ${result.target_version}`);
        await this.performUpdate();
      }
    } catch (error) {
      console.error('❌ Error sending metrics:', error);
    }
  }

  async sendProcesses() {
    try {
      const processes = await this.processCollector.collectAll();

      if (processes.length === 0) {
        return; // No processes to monitor
      }

      console.log(`🔍 Checking monitored processes...`);
      processes.forEach(proc => {
        const status = proc.isRunning ? '✅' : '❌';
        console.log(`   ${status} ${proc.name} (PID: ${proc.pid || 'N/A'})`);
      });

      const response = await fetch(`${API_URL}/api/processes`, {
        method: 'POST',
        headers: {
          'Content-Type': 'application/json',
          'X-API-Key': API_KEY,
        },
        body: JSON.stringify({ processes }),
      });

      if (!response.ok) {
        const error = await response.text();
        console.error(`❌ Failed to send processes: ${response.status} - ${error}`);
      }
    } catch (error) {
      console.error('❌ Error sending processes:', error);
    }
  }

  async sendSecurityAudits() {
    try {
      const audits = await this.securityCollector.collectAll();

      if (audits.length === 0) {
        console.log(`🔒 Security check: No issues detected`);
        return;
      }

      console.log(`🔒 Security audits collected (${audits.length})...`);
      audits.forEach(audit => {
        const icon = audit.severity === 'critical' ? '🚨' : audit.severity === 'warning' ? '⚠️' : 'ℹ️';
        console.log(`   ${icon} ${audit.type}: ${audit.description}`);
      });

      const response = await fetch(`${API_URL}/api/security`, {
        method: 'POST',
        headers: {
          'Content-Type': 'application/json',
          'X-API-Key': API_KEY,
        },
        body: JSON.stringify({ audits }),
      });

      if (!response.ok) {
        const error = await response.text();
        console.error(`❌ Failed to send security audits: ${response.status} - ${error}`);
      }
    } catch (error) {
      console.error('❌ Error sending security audits:', error);
    }
  }

  async performUpdate() {
    try {
      console.log('🔄 Starting update process...');
      
      const updateScriptPath = path.join(__dirname, '../update.sh');
      
      if (!fs.existsSync(updateScriptPath)) {
        console.error('❌ Update script not found at', updateScriptPath);
        return;
      }

      console.log('🔄 Executing update script...');
      const { stdout, stderr } = await execAsync(updateScriptPath);
      
      if (stdout) console.log(stdout);
      if (stderr) console.error(stderr);
      
      console.log('✅ Update completed successfully');
    } catch (error) {
      console.error('❌ Update failed:', error);
    }
  }

  start() {
    console.log('🚀 Monitoring Agent starting...');
    console.log(`   Server: ${SERVER_NAME}`);
    console.log(`   API URL: ${API_URL}`);
    console.log(`   Interval: ${INTERVAL_SECONDS}s`);
    console.log(`   Monitored processes: ${MONITORED_PROCESSES.join(', ')}`);
    console.log(`   Agent Version: ${AGENT_VERSION}\n`);

    // Send all data immediately
    this.sendMetrics();
    this.sendProcesses();
    this.sendSecurityAudits();

    // Send metrics and processes at regular intervals
    this.intervalId = setInterval(() => {
      this.sendMetrics();
      this.sendProcesses();
    }, INTERVAL_SECONDS * 1000);

    // Security audits less frequently (every 5 minutes)
    this.securityIntervalId = setInterval(() => {
      this.sendSecurityAudits();
    }, 5 * 60 * 1000);
  }

  stop() {
    if (this.intervalId) {
      clearInterval(this.intervalId);
    }
    if (this.securityIntervalId) {
      clearInterval(this.securityIntervalId);
    }
    console.log('🛑 Monitoring Agent stopped');
  }
}

// Start agent
const agent = new MonitoringAgent();
agent.start();

// Graceful shutdown
process.on('SIGTERM', () => {
  console.log('\nSIGTERM received, shutting down gracefully...');
  agent.stop();
  process.exit(0);
});

process.on('SIGINT', () => {
  console.log('\nSIGINT received, shutting down gracefully...');
  agent.stop();
  process.exit(0);
});
