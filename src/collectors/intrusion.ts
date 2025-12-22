import { exec } from 'child_process';
import { promisify } from 'util';
import fs from 'fs/promises';

const execAsync = promisify(exec);

export interface IntrusionDetection {
  type: string;
  severity: 'info' | 'warning' | 'critical';
  description: string;
  details: Record<string, any>;
}

export class IntrusionCollector {
  async collectAll(): Promise<IntrusionDetection[]> {
    const detections: IntrusionDetection[] = [];

    try {
      const [
        suspiciousUsers,
        suspiciousProcesses,
        recentLogins,
      ] = await Promise.all([
        this.checkSuspiciousUsers(),
        this.checkSuspiciousProcesses(),
        this.checkRecentLogins(),
      ]);

      if (suspiciousUsers) detections.push(suspiciousUsers);
      if (suspiciousProcesses) detections.push(suspiciousProcesses);
      if (recentLogins) detections.push(recentLogins);
    } catch (error) {
      console.error('Error collecting intrusion detections:', error);
    }

    return detections;
  }

  private async checkSuspiciousUsers(): Promise<IntrusionDetection | null> {
    try {
      // Get all users with shell access
      const { stdout } = await execAsync(
        `cat /etc/passwd | grep -v nologin | grep -v false | awk -F: '$3 >= 1000 {print $1":"$3":"$6":"$7}'`
      );

      const users = stdout.trim().split('\n').filter(line => line.length > 0);
      
      // Get recently created users (last 30 days)
      const { stdout: recentStdout } = await execAsync(
        `sudo find /home -maxdepth 1 -type d -mtime -30 -printf "%f\\n" 2>/dev/null || echo ""`
      );

      const recentUsers = recentStdout.trim().split('\n').filter(u => u && u !== 'home');

      // Check for users with UID 0 (root privileges)
      const { stdout: rootUsersStdout } = await execAsync(
        `awk -F: '$3 == 0 {print $1}' /etc/passwd`
      );

      const rootUsers = rootUsersStdout.trim().split('\n').filter(u => u !== 'root');

      const suspiciousCount = recentUsers.length + rootUsers.length;

      if (suspiciousCount === 0 && users.length <= 5) {
        return null; // Nothing suspicious
      }

      return {
        type: 'suspicious_users',
        severity: rootUsers.length > 0 ? 'critical' : recentUsers.length > 2 ? 'warning' : 'info',
        description: `${users.length} users with shell access detected`,
        details: {
          totalUsers: users.length,
          recentUsers: recentUsers,
          rootPrivilegeUsers: rootUsers,
          allUsers: users.map(u => {
            const [name, uid, home, shell] = u.split(':');
            return { name, uid, home, shell };
          }),
        },
      };
    } catch (error) {
      console.error('Error checking users:', error);
      return null;
    }
  }

  private async checkSuspiciousProcesses(): Promise<IntrusionDetection | null> {
    try {
      // List of commonly suspicious process names
      const suspiciousNames = [
        'nc', 'netcat', 'ncat',  // Network tools
        'mimikatz', 'metasploit',  // Hacking tools
        'cryptominer', 'xmrig', 'minerd',  // Crypto miners
        '.hidden', '...',  // Hidden processes
      ];

      const { stdout } = await execAsync(
        `ps aux --no-headers | awk '{print $1":"$2":"$11}' | head -100`
      );

      const processes = stdout.trim().split('\n');
      const suspicious: any[] = [];

      processes.forEach(proc => {
        const [user, pid, cmd] = proc.split(':');
        const cmdLower = cmd.toLowerCase();
        
        suspiciousNames.forEach(suspName => {
          if (cmdLower.includes(suspName)) {
            suspicious.push({ user, pid, command: cmd, reason: `Suspicious command: ${suspName}` });
          }
        });

        // Check for processes running from /tmp or /dev/shm
        if (cmdLower.includes('/tmp/') || cmdLower.includes('/dev/shm/')) {
          suspicious.push({ user, pid, command: cmd, reason: 'Running from suspicious location' });
        }
      });

      if (suspicious.length === 0) {
        return null;
      }

      return {
        type: 'suspicious_processes',
        severity: suspicious.length > 5 ? 'critical' : suspicious.length > 2 ? 'warning' : 'info',
        description: `${suspicious.length} suspicious process(es) detected`,
        details: {
          count: suspicious.length,
          processes: suspicious,
        },
      };
    } catch (error) {
      console.error('Error checking processes:', error);
      return null;
    }
  }

  private async checkRecentLogins(): Promise<IntrusionDetection | null> {
    try {
      // Get last 20 logins
      const { stdout } = await execAsync(
        `last -20 -w -F | grep -v "^$" | grep -v "^wtmp" | head -20`
      );

      const logins = stdout.trim().split('\n').filter(line => line.length > 0);

      // Parse login information
      const loginInfo = logins.map(line => {
        const parts = line.split(/\s+/);
        return {
          user: parts[0],
          terminal: parts[1],
          ip: parts[2],
          timestamp: parts.slice(3, 8).join(' '),
        };
      });

      // Count unique IPs
      const uniqueIps = new Set(loginInfo.map(l => l.ip).filter(ip => ip !== 'localhost'));

      return {
        type: 'recent_logins',
        severity: uniqueIps.size > 5 ? 'warning' : 'info',
        description: `${logins.length} recent logins from ${uniqueIps.size} unique IPs`,
        details: {
          count: logins.length,
          uniqueIps: Array.from(uniqueIps),
          recentLogins: loginInfo.slice(0, 10),
        },
      };
    } catch (error) {
      console.error('Error checking logins:', error);
      return null;
    }
  }
}
