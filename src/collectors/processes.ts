import { exec } from 'child_process';
import { promisify } from 'util';

const execAsync = promisify(exec);

export interface ProcessInfo {
  name: string;
  pid: number;
  status: string;
  cpuPercent: number;
  memoryPercent: number;
  isRunning: boolean;
}

export interface ProcessMonitorConfig {
  processes: string[]; // Process names to monitor (e.g., ['nginx', 'postgresql', 'node'])
}

export class ProcessCollector {
  private config: ProcessMonitorConfig;

  constructor(config: ProcessMonitorConfig = { processes: [] }) {
    this.config = config;
  }

  async collectAll(): Promise<ProcessInfo[]> {
    const processInfos: ProcessInfo[] = [];

    // Get configured processes
    for (const processName of this.config.processes) {
      const info = await this.getProcessInfo(processName);
      if (info) {
        processInfos.push(info);
      }
    }

    // Also get top 10 processes by memory usage
    const topProcesses = await this.getTopProcessesByMemory(10);
    processInfos.push(...topProcesses);

    return processInfos;
  }

  private async getTopProcessesByMemory(limit: number = 10): Promise<ProcessInfo[]> {
    try {
      // Get top processes by memory, exclude kernel threads and system processes
      const { stdout } = await execAsync(
        `ps aux --sort=-%mem | grep -v "\\[" | head -n ${limit + 1} | tail -n ${limit}`
      );

      const lines = stdout.trim().split('\n');
      const processes: ProcessInfo[] = [];

      for (const line of lines) {
        if (!line.trim()) continue;

        const parts = line.trim().split(/\s+/);
        if (parts.length < 11) continue;

        const pid = parseInt(parts[1]);
        const cpuPercent = parseFloat(parts[2]);
        const memoryPercent = parseFloat(parts[3]);
        const status = parts[7];
        const command = parts.slice(10).join(' ');
        
        // Extract meaningful process name from command
        let processName = command.split(' ')[0].split('/').pop() || command;
        
        // For Node.js processes, try to extract what they're running
        if (processName === 'node') {
          // Look for common patterns in the command
          if (command.includes('.vscode-server')) {
            processName = 'node:vscode-server';
          } else if (command.includes('vite')) {
            processName = 'node:vite';
          } else if (command.includes('ts-node')) {
            processName = 'node:ts-node';
          } else if (command.includes('nodemon')) {
            processName = 'node:nodemon';
          } else if (command.includes('/pm2/')) {
            processName = 'node:pm2';
          } else if (command.includes('monitor-agent')) {
            processName = 'node:agent';
          } else if (command.includes('monitor-api')) {
            processName = 'node:api';
          } else if (command.includes('monitor-dashboard')) {
            processName = 'node:dashboard';
          } else {
            // Try to get the script name
            const scriptMatch = command.match(/node\s+([^\s]+\.js|[^\s]+\.ts)/);
            if (scriptMatch) {
              const script = scriptMatch[1].split('/').pop()?.replace(/\.(js|ts)$/, '');
              processName = `node:${script}`;
            }
          }
        }

        processes.push({
          name: processName,
          pid,
          status,
          cpuPercent: Math.round(cpuPercent * 100) / 100,
          memoryPercent: Math.round(memoryPercent * 100) / 100,
          isRunning: true,
        });
      }

      return processes;
    } catch (error) {
      console.error('Error getting top processes:', error);
      return [];
    }
  }

  private async getProcessInfo(processName: string): Promise<ProcessInfo | null> {
    try {
      // Use ps to find process by name
      // Format: PID %CPU %MEM STAT COMMAND
      const { stdout } = await execAsync(
        `ps aux | grep -v grep | grep -E "${processName}" | head -1`
      );

      if (!stdout.trim()) {
        // Process not running
        return {
          name: processName,
          pid: 0,
          status: 'not_running',
          cpuPercent: 0,
          memoryPercent: 0,
          isRunning: false,
        };
      }

      // Parse ps output
      const parts = stdout.trim().split(/\s+/);
      
      // ps aux format: USER PID %CPU %MEM VSZ RSS TTY STAT START TIME COMMAND
      const pid = parseInt(parts[1]);
      const cpuPercent = parseFloat(parts[2]);
      const memoryPercent = parseFloat(parts[3]);
      const status = parts[7]; // STAT column

      return {
        name: processName,
        pid,
        status,
        cpuPercent: Math.round(cpuPercent * 100) / 100,
        memoryPercent: Math.round(memoryPercent * 100) / 100,
        isRunning: true,
      };
    } catch (error) {
      // If command fails, process is not running
      return {
        name: processName,
        pid: 0,
        status: 'not_running',
        cpuPercent: 0,
        memoryPercent: 0,
        isRunning: false,
      };
    }
  }

  // Add process to monitor
  addProcess(processName: string) {
    if (!this.config.processes.includes(processName)) {
      this.config.processes.push(processName);
    }
  }

  // Remove process from monitoring
  removeProcess(processName: string) {
    this.config.processes = this.config.processes.filter(p => p !== processName);
  }

  // Get list of monitored processes
  getMonitoredProcesses(): string[] {
    return [...this.config.processes];
  }
}
