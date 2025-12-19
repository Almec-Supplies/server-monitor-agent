import os from 'os';
import { exec } from 'child_process';
import { promisify } from 'util';

const execAsync = promisify(exec);

export interface SystemMetrics {
  cpu: {
    usage: number;
    count: number;
    loadAverage: [number, number, number];
  };
  memory: {
    total: number;
    used: number;
    free: number;
    usagePercent: number;
  };
  disk: {
    total: number;
    used: number;
    free: number;
    usagePercent: number;
  };
  network: {
    bytesSent: number;
    bytesRecv: number;
  };
  system: {
    uptime: number;
    platform: string;
    hostname: string;
  };
}

export class MetricsCollector {
  private previousCpuInfo: { idle: number; total: number } | null = null;
  private previousNetworkInfo: { bytesSent: number; bytesRecv: number; timestamp: number } | null = null;

  async collectAll(): Promise<SystemMetrics> {
    const [cpu, memory, disk, network, system] = await Promise.all([
      this.collectCPU(),
      this.collectMemory(),
      this.collectDisk(),
      this.collectNetwork(),
      this.collectSystem(),
    ]);

    return { cpu, memory, disk, network, system };
  }

  private async collectCPU() {
    const cpus = os.cpus();
    const loadAverage = os.loadavg() as [number, number, number];

    // Calculate CPU usage
    let idle = 0;
    let total = 0;

    cpus.forEach((cpu) => {
      for (const type in cpu.times) {
        total += cpu.times[type as keyof typeof cpu.times];
      }
      idle += cpu.times.idle;
    });

    let usage = 0;
    if (this.previousCpuInfo) {
      const idleDiff = idle - this.previousCpuInfo.idle;
      const totalDiff = total - this.previousCpuInfo.total;
      usage = 100 - (100 * idleDiff) / totalDiff;
    }

    this.previousCpuInfo = { idle, total };

    return {
      usage: Math.round(usage * 100) / 100,
      count: cpus.length,
      loadAverage,
    };
  }

  private async collectMemory() {
    const total = os.totalmem();
    const free = os.freemem();
    const used = total - free;
    const usagePercent = (used / total) * 100;

    return {
      total,
      used,
      free,
      usagePercent: Math.round(usagePercent * 100) / 100,
    };
  }

  private async collectDisk() {
    try {
      // Use 'df' command to get disk usage
      const { stdout } = await execAsync('df -B1 / | tail -1');
      const parts = stdout.trim().split(/\s+/);

      const total = parseInt(parts[1]);
      const used = parseInt(parts[2]);
      const free = parseInt(parts[3]);
      const usagePercent = parseFloat(parts[4]);

      return { total, used, free, usagePercent };
    } catch (error) {
      console.error('Error collecting disk metrics:', error);
      return { total: 0, used: 0, free: 0, usagePercent: 0 };
    }
  }

  private async collectNetwork() {
    try {
      // Read network stats from /proc/net/dev
      const { stdout } = await execAsync('cat /proc/net/dev');
      const lines = stdout.split('\n');

      let totalBytesSent = 0;
      let totalBytesRecv = 0;

      lines.forEach((line) => {
        if (line.includes(':') && !line.includes('lo:')) {
          const parts = line.split(/\s+/).filter(p => p);
          const iface = parts[0].replace(':', '');
          // Skip docker interfaces and other virtual interfaces
          if (!iface.startsWith('docker') && !iface.startsWith('veth') && !iface.startsWith('br-')) {
            totalBytesRecv += parseInt(parts[1]) || 0;
            totalBytesSent += parseInt(parts[9]) || 0;
          }
        }
      });

      const now = Date.now();
      let bytesSent = 0;
      let bytesRecv = 0;

      // Calculate rate (bytes per interval)
      if (this.previousNetworkInfo) {
        const timeDiff = (now - this.previousNetworkInfo.timestamp) / 1000; // seconds
        if (timeDiff > 0) {
          bytesSent = Math.max(0, totalBytesSent - this.previousNetworkInfo.bytesSent);
          bytesRecv = Math.max(0, totalBytesRecv - this.previousNetworkInfo.bytesRecv);
        }
      }

      this.previousNetworkInfo = { 
        bytesSent: totalBytesSent, 
        bytesRecv: totalBytesRecv,
        timestamp: now
      };

      return { bytesSent, bytesRecv };
    } catch (error) {
      console.error('Error collecting network metrics:', error);
      return { bytesSent: 0, bytesRecv: 0 };
    }
  }

  private async collectSystem() {
    return {
      uptime: Math.floor(os.uptime()),
      platform: os.platform(),
      hostname: os.hostname(),
    };
  }
}
