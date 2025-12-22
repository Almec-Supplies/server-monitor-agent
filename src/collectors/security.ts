import { exec } from 'child_process';
import { promisify } from 'util';
import fs from 'fs/promises';

const execAsync = promisify(exec);

export interface SecurityAudit {
  type: string;
  severity: 'info' | 'warning' | 'critical';
  description: string;
  details: Record<string, any>;
}

export class SecurityCollector {
  async collectAll(): Promise<SecurityAudit[]> {
    const audits: SecurityAudit[] = [];

    try {
      // Run all security checks in parallel
      const [
        failedLogins,
        openPorts,
        pendingUpdates,
        firewallStatus,
        sensitiveFiles,
        fail2banStatus,
      ] = await Promise.all([
        this.checkFailedSSHLogins(),
        this.checkOpenPorts(),
        this.checkPendingUpdates(),
        this.checkFirewallStatus(),
        this.checkSensitiveFiles(),
        this.checkFail2ban(),
      ]);

      if (failedLogins) audits.push(failedLogins);
      if (openPorts) audits.push(openPorts);
      if (pendingUpdates) audits.push(pendingUpdates);
      if (firewallStatus) audits.push(firewallStatus);
      if (sensitiveFiles) audits.push(sensitiveFiles);
      if (fail2banStatus) audits.push(fail2banStatus);
    } catch (error) {
      console.error('Error collecting security audits:', error);
    }

    return audits;
  }

  private async checkFailedSSHLogins(): Promise<SecurityAudit | null> {
    try {
      // Check for failed SSH login attempts in the last 24 hours
      const { stdout } = await execAsync(
        `sudo grep "Failed password" /var/log/auth.log 2>/dev/null | tail -50 || echo ""`
      );

      const failedAttempts = stdout.trim().split('\n').filter(line => line.length > 0);
      const count = failedAttempts.length;

      if (count === 0) {
        return null; // No failed attempts, no need to report
      }

      // Extract unique IPs
      const ipPattern = /from\s+(\d+\.\d+\.\d+\.\d+)/g;
      const ips = new Set<string>();
      failedAttempts.forEach(line => {
        const match = line.match(ipPattern);
        if (match) {
          const ip = match[0].replace('from ', '');
          ips.add(ip);
        }
      });

      return {
        type: 'failed_ssh_logins',
        severity: count > 10 ? 'critical' : count > 5 ? 'warning' : 'info',
        description: `${count} failed SSH login attempts detected`,
        details: {
          count,
          uniqueIps: Array.from(ips),
          recentAttempts: failedAttempts.slice(0, 5), // Last 5 attempts
        },
      };
    } catch (error) {
      // Auth log might not be accessible or doesn't exist
      return null;
    }
  }

  private async checkOpenPorts(): Promise<SecurityAudit | null> {
    try {
      // Use ss to list listening ports
      const { stdout } = await execAsync(
        `ss -tuln | grep LISTEN | awk '{print $5}' | sed 's/.*://g' | sort -u`
      );

      const ports = stdout
        .trim()
        .split('\n')
        .filter(p => p && !isNaN(parseInt(p)))
        .map(p => parseInt(p));

      // Common ports that should be monitored
      const commonPorts: Record<number, string> = {
        22: 'SSH',
        80: 'HTTP',
        443: 'HTTPS',
        3306: 'MySQL',
        5432: 'PostgreSQL',
        6379: 'Redis',
        27017: 'MongoDB',
        3000: 'Development Server',
        5000: 'API Server',
        8080: 'HTTP Alt',
      };

      const openPortsInfo = ports.map(port => ({
        port,
        service: commonPorts[port] || 'Unknown',
      }));

      return {
        type: 'open_ports',
        severity: 'info',
        description: `${ports.length} listening ports detected`,
        details: {
          count: ports.length,
          ports: openPortsInfo,
        },
      };
    } catch (error) {
      return null;
    }
  }

  private async checkPendingUpdates(): Promise<SecurityAudit | null> {
    try {
      // Check for pending security updates (Ubuntu/Debian)
      const { stdout } = await execAsync(
        `apt list --upgradable 2>/dev/null | grep -i security | wc -l || echo "0"`
      );

      const securityUpdates = parseInt(stdout.trim());

      // Check total updates
      const { stdout: totalStdout } = await execAsync(
        `apt list --upgradable 2>/dev/null | grep -v "Listing" | wc -l || echo "0"`
      );

      const totalUpdates = parseInt(totalStdout.trim());

      if (totalUpdates === 0) {
        return null; // System up to date
      }

      return {
        type: 'pending_updates',
        severity: securityUpdates > 0 ? 'warning' : 'info',
        description: `${totalUpdates} pending updates (${securityUpdates} security)`,
        details: {
          total: totalUpdates,
          security: securityUpdates,
        },
      };
    } catch (error) {
      // apt might not be available on non-Debian systems
      return null;
    }
  }

  private async checkFirewallStatus(): Promise<SecurityAudit | null> {
    try {
      // Check UFW status (Ubuntu default firewall)
      const { stdout } = await execAsync(`sudo ufw status 2>/dev/null || echo "inactive"`);

      const isActive = stdout.toLowerCase().includes('status: active');
      const rules = stdout.split('\n').filter(line => line.match(/\d+\/(tcp|udp)/)).length;

      return {
        type: 'firewall_status',
        severity: !isActive ? 'warning' : 'info',
        description: isActive ? `Firewall active with ${rules} rules` : 'Firewall is inactive',
        details: {
          active: isActive,
          rules: rules,
          output: stdout.split('\n').slice(0, 10), // First 10 lines
        },
      };
    } catch (error) {
      // UFW might not be available
      try {
        // Try iptables as fallback
        const { stdout } = await execAsync(`sudo iptables -L -n 2>/dev/null | wc -l`);
        const ruleCount = parseInt(stdout.trim());
        
        return {
          type: 'firewall_status',
          severity: ruleCount < 5 ? 'warning' : 'info',
          description: `iptables has ${ruleCount} rules`,
          details: {
            active: ruleCount > 0,
            rules: ruleCount,
            tool: 'iptables',
          },
        };
      } catch {
        return {
          type: 'firewall_status',
          severity: 'warning',
          description: 'Unable to determine firewall status',
          details: {
            active: false,
            error: 'No firewall detected',
          },
        };
      }
    }
  }

  private async checkSensitiveFiles(): Promise<SecurityAudit | null> {
    try {
      // Find nginx document roots
      const { stdout: nginxRoots } = await execAsync(
        `sudo grep -r "root " /etc/nginx/sites-enabled/ 2>/dev/null | grep -v "#" | awk '{print $NF}' | tr -d ';' | sort -u || echo ""`
      );

      if (!nginxRoots.trim()) {
        return null;
      }

      const roots = nginxRoots.trim().split('\n').filter(r => r.length > 0);
      const sensitivePatterns = ['.env', '.git', 'config.php', '.htaccess', 'wp-config.php', 'database.yml'];
      const foundFiles: Array<{ file: string; path: string }> = [];

      for (const root of roots) {
        for (const pattern of sensitivePatterns) {
          try {
            const { stdout } = await execAsync(
              `sudo test -e ${root}/${pattern} && echo "found" || echo ""`
            );
            if (stdout.includes('found')) {
              foundFiles.push({ file: pattern, path: `${root}/${pattern}` });
            }
          } catch {
            continue;
          }
        }
      }

      if (foundFiles.length === 0) {
        return {
          type: 'sensitive_files',
          severity: 'info',
          description: 'No sensitive files exposed in web root',
          details: {
            count: 0,
            files: [],
            roots: roots,
            checked: sensitivePatterns,
          },
        };
      }

      return {
        type: 'sensitive_files',
        severity: 'critical',
        description: `${foundFiles.length} sensitive file(s) in web root`,
        details: {
          count: foundFiles.length,
          files: foundFiles,
          roots: roots,
        },
      };
    } catch (error) {
      return null;
    }
  }

  private async checkFail2ban(): Promise<SecurityAudit | null> {
    try {
      // Check if fail2ban is installed and running
      const { stdout: statusOutput } = await execAsync(
        `sudo systemctl is-active fail2ban 2>/dev/null || echo "inactive"`
      );

      const isActive = statusOutput.trim() === 'active';

      if (!isActive) {
        return {
          type: 'fail2ban_status',
          severity: 'warning',
          description: 'Fail2ban is not active',
          details: {
            active: false,
            installed: false,
          },
        };
      }

      // Get banned IPs count
      const { stdout: bannedOutput } = await execAsync(
        `sudo fail2ban-client status 2>/dev/null | grep "Jail list" | sed 's/.*://; s/,//g' || echo ""`
      );

      const jails = bannedOutput.trim().split(/\s+/).filter(j => j.length > 0);
      let totalBanned = 0;
      const jailInfo: Array<{ jail: string; banned: number }> = [];

      for (const jail of jails) {
        try {
          const { stdout } = await execAsync(
            `sudo fail2ban-client status ${jail} 2>/dev/null | grep "Currently banned" | awk '{print $NF}' || echo "0"`
          );
          const banned = parseInt(stdout.trim()) || 0;
          totalBanned += banned;
          if (banned > 0) {
            jailInfo.push({ jail, banned });
          }
        } catch {
          continue;
        }
      }

      return {
        type: 'fail2ban_status',
        severity: 'info',
        description: `Fail2ban active - ${totalBanned} IP(s) banned`,
        details: {
          active: true,
          installed: true,
          totalBanned,
          jails: jailInfo,
          jailCount: jails.length,
        },
      };
    } catch (error) {
      return null;
    }
  }
}
