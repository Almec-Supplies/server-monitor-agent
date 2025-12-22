import { exec } from 'child_process';
import { promisify } from 'util';
import fs from 'fs/promises';

const execAsync = promisify(exec);

export interface ErrorLogReport {
  source: string;
  severity: 'info' | 'warning' | 'critical';
  errorCount: number;
  warningCount: number;
  criticalCount: number;
  recentErrors: Array<{ timestamp: string; level: string; message: string }>;
}

export class ErrorLogsCollector {
  async collectAll(): Promise<ErrorLogReport[]> {
    const reports: ErrorLogReport[] = [];

    try {
      const [nginxReport, phpReport] = await Promise.all([
        this.checkNginxErrors(),
        this.checkPhpErrors(),
      ]);

      if (nginxReport) reports.push(nginxReport);
      if (phpReport) reports.push(phpReport);
    } catch (error) {
      console.error('Error collecting error logs:', error);
    }

    return reports;
  }

  private async checkNginxErrors(): Promise<ErrorLogReport | null> {
    try {
      // Find all nginx error log files (including virtual host logs)
      const { stdout: logFiles } = await execAsync(
        `sudo find /var/log/nginx -name "*.error.log" -type f 2>/dev/null || echo ""`
      );

      if (!logFiles.trim()) {
        return null;
      }

      const files = logFiles.trim().split('\n').filter(f => f.length > 0);
      
      let totalErrorCount = 0;
      let totalWarningCount = 0;
      let totalCriticalCount = 0;
      const allRecentErrors: Array<{ timestamp: string; level: string; message: string }> = [];

      // Process each error log file
      for (const errorLogPath of files) {
        try {
          // Count errors by severity (last 500 lines per file)
          const { stdout } = await execAsync(
            `sudo tail -500 ${errorLogPath} 2>/dev/null || echo ""`
          );

          if (!stdout.trim()) {
            continue;
          }

          const lines = stdout.trim().split('\n');
          
          lines.forEach(line => {
            if (line.includes('[error]')) {
              totalErrorCount++;
              if (allRecentErrors.length < 10) {
                allRecentErrors.push(this.parseNginxLogLine(line, 'error'));
              }
            } else if (line.includes('[warn]')) {
              totalWarningCount++;
              if (allRecentErrors.length < 10) {
                allRecentErrors.push(this.parseNginxLogLine(line, 'warning'));
              }
            } else if (line.includes('[crit]') || line.includes('[alert]') || line.includes('[emerg]')) {
              totalCriticalCount++;
              if (allRecentErrors.length < 10) {
                allRecentErrors.push(this.parseNginxLogLine(line, 'critical'));
              }
            }
          });
        } catch (error) {
          // Skip this file if we can't read it
          continue;
        }
      }

      const totalErrors = totalErrorCount + totalWarningCount + totalCriticalCount;

      if (totalErrors === 0) {
        return null;
      }

      return {
        source: 'nginx',
        severity: totalCriticalCount > 0 ? 'critical' : totalErrorCount > 100 ? 'warning' : 'info',
        errorCount: totalErrorCount,
        warningCount: totalWarningCount,
        criticalCount: totalCriticalCount,
        recentErrors: allRecentErrors.slice(0, 5),
      };
    } catch (error) {
      console.error('Error checking nginx logs:', error);
      return null;
    }
  }

  private async checkPhpErrors(): Promise<ErrorLogReport | null> {
    try {
      // Common PHP error log locations
      const phpLogPaths = [
        '/var/log/php-fpm/error.log',
        '/var/log/php/error.log',
        '/var/log/php7.4-fpm.log',
        '/var/log/php8.1-fpm.log',
        '/var/log/php8.2-fpm.log',
      ];

      let logPath: string | null = null;

      // Find first existing log
      for (const path of phpLogPaths) {
        try {
          const { stdout } = await execAsync(
            `sudo test -f ${path} && echo "exists" || echo "missing"`
          );
          if (stdout.includes('exists')) {
            logPath = path;
            break;
          }
        } catch {
          continue;
        }
      }

      if (!logPath) {
        return null; // No PHP logs found
      }

      // Count errors by severity (last 1000 lines)
      const { stdout } = await execAsync(
        `sudo tail -1000 ${logPath} 2>/dev/null || echo ""`
      );

      if (!stdout.trim()) {
        return null;
      }

      const lines = stdout.trim().split('\n');
      let errorCount = 0;
      let warningCount = 0;
      let criticalCount = 0;
      const recentErrors: Array<{ timestamp: string; level: string; message: string }> = [];

      lines.forEach(line => {
        const lineLower = line.toLowerCase();
        
        if (lineLower.includes('fatal error') || lineLower.includes('parse error')) {
          criticalCount++;
          if (recentErrors.length < 5) {
            recentErrors.push(this.parsePhpLogLine(line, 'critical'));
          }
        } else if (lineLower.includes('error') || lineLower.includes('exception')) {
          errorCount++;
          if (recentErrors.length < 5) {
            recentErrors.push(this.parsePhpLogLine(line, 'error'));
          }
        } else if (lineLower.includes('warning') || lineLower.includes('notice')) {
          warningCount++;
          if (recentErrors.length < 5) {
            recentErrors.push(this.parsePhpLogLine(line, 'warning'));
          }
        }
      });

      const totalErrors = errorCount + warningCount + criticalCount;

      if (totalErrors === 0) {
        return null;
      }

      return {
        source: 'php',
        severity: criticalCount > 0 ? 'critical' : errorCount > 50 ? 'warning' : 'info',
        errorCount,
        warningCount,
        criticalCount,
        recentErrors: recentErrors.slice(0, 5),
      };
    } catch (error) {
      console.error('Error checking PHP logs:', error);
      return null;
    }
  }

  private parseNginxLogLine(line: string, level: string): { timestamp: string; level: string; message: string } {
    // Nginx format: 2024/12/22 10:30:45 [error] 12345#12345: *1 message
    const match = line.match(/^(\d{4}\/\d{2}\/\d{2} \d{2}:\d{2}:\d{2})\s+\[(\w+)\]\s+(.+)$/);
    
    if (match) {
      return {
        timestamp: match[1],
        level: match[2],
        message: match[3].substring(0, 200), // Truncate long messages
      };
    }

    return {
      timestamp: 'Unknown',
      level,
      message: line.substring(0, 200),
    };
  }

  private parsePhpLogLine(line: string, level: string): { timestamp: string; level: string; message: string } {
    // PHP format: [22-Dec-2024 10:30:45 Europe/Amsterdam] PHP Warning: message
    const match = line.match(/^\[([^\]]+)\]\s+(.+)$/);
    
    if (match) {
      return {
        timestamp: match[1],
        level,
        message: match[2].substring(0, 200),
      };
    }

    return {
      timestamp: 'Unknown',
      level,
      message: line.substring(0, 200),
    };
  }
}
