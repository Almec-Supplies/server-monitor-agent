import { exec } from 'child_process';
import { promisify } from 'util';
import * as https from 'https';
import * as http from 'http';
import * as tls from 'tls';
import * as fs from 'fs/promises';

const execAsync = promisify(exec);

export interface Site {
  domain: string;
  configPath: string;
  isEnabled: boolean;
  port: number;
  isSsl: boolean;
  sslCertPath?: string;
  sslCertExpiry?: Date;
  sslDaysRemaining?: number;
  isReachable: boolean;
  httpStatusCode?: number;
  responseTimeMs?: number;
}

export class SitesCollector {
  async collectAll(): Promise<Site[]> {
    const sites: Site[] = [];

    try {
      // Find nginx sites
      const nginxSites = await this.getNginxSites();
      
      // Remove duplicates (same domain, keep SSL version)
      const uniqueSites = new Map<string, typeof nginxSites[0]>();
      for (const site of nginxSites) {
        const existing = uniqueSites.get(site.domain);
        if (!existing || (site.isSsl && !existing.isSsl)) {
          uniqueSites.set(site.domain, site);
        }
      }
      
      // Check each unique site with rate limiting (3 concurrent max)
      const sitesArray = Array.from(uniqueSites.values());
      for (let i = 0; i < sitesArray.length; i += 3) {
        const batch = sitesArray.slice(i, i + 3);
        const batchResults = await Promise.all(batch.map(site => this.checkSite(site)));
        sites.push(...batchResults);
        
        // Small delay between batches to avoid overwhelming the server
        if (i + 3 < sitesArray.length) {
          await new Promise(resolve => setTimeout(resolve, 2000));
        }
      }
    } catch (error) {
      console.error('Error collecting sites:', error);
    }

    return sites;
  }

  private async getNginxSites(): Promise<{ domain: string; configPath: string; isEnabled: boolean; port: number; isSsl: boolean; sslCertPath?: string }[]> {
    const sites: { domain: string; configPath: string; isEnabled: boolean; port: number; isSsl: boolean; sslCertPath?: string }[] = [];

    try {
      // Check if nginx config directories exist (more reliable than checking nginx binary)
      const nginxConfigExists = await this.pathExists('/etc/nginx');
      if (!nginxConfigExists) {
        return sites; // Nginx not installed
      }

      // Standard nginx paths
      const enabledSitesPath = '/etc/nginx/sites-enabled';
      const availableSitesPath = '/etc/nginx/sites-available';
      
      // Plesk nginx paths
      const pleskVhostsPath = '/var/www/vhosts/system';
      const pleskConfPath = '/etc/nginx/plesk.conf.d';

      // Get standard enabled sites
      try {
        const { stdout: enabledFiles } = await execAsync(`ls ${enabledSitesPath} 2>/dev/null || echo ""`);
        const enabledSiteFiles = enabledFiles.trim().split('\n').filter(f => f && f !== 'default');

        for (const file of enabledSiteFiles) {
          const configPath = `${enabledSitesPath}/${file}`;
          const siteInfo = await this.parseNginxConfig(configPath, true);
          if (siteInfo) {
            sites.push(siteInfo);
          }
        }
      } catch (err) {
        console.error('Error reading enabled sites:', err);
      }

      // Check standard available but not enabled sites
      try {
        const { stdout: availableFiles } = await execAsync(`ls ${availableSitesPath} 2>/dev/null || echo ""`);
        const availableSiteFiles = availableFiles.trim().split('\n').filter(f => f && f !== 'default');
        const { stdout: enabledFiles } = await execAsync(`ls ${enabledSitesPath} 2>/dev/null || echo ""`);
        const enabledNames = new Set(enabledFiles.trim().split('\n'));

        for (const file of availableSiteFiles) {
          if (!enabledNames.has(file)) {
            const configPath = `${availableSitesPath}/${file}`;
            const siteInfo = await this.parseNginxConfig(configPath, false);
            if (siteInfo) {
              sites.push(siteInfo);
            }
          }
        }
      } catch (err) {
        console.error('Error reading available sites:', err);
      }

      // Check for Plesk vhosts configurations
      try {
        const { stdout: pleskDomains } = await execAsync(`find ${pleskVhostsPath} -maxdepth 2 -name "nginx.conf" 2>/dev/null || echo ""`);
        const pleskConfigFiles = pleskDomains.trim().split('\n').filter(f => f);

        for (const configPath of pleskConfigFiles) {
          const siteInfo = await this.parseNginxConfig(configPath, true);
          if (siteInfo) {
            sites.push({ ...siteInfo, configPath: configPath + ' (Plesk)' });
          }
        }
      } catch (err) {
        console.error('Error reading Plesk vhosts:', err);
      }

      // Check Plesk conf.d directory
      try {
        const { stdout: pleskConfFiles } = await execAsync(`ls ${pleskConfPath}/vhosts/*.conf 2>/dev/null || echo ""`);
        const pleskFiles = pleskConfFiles.trim().split('\n').filter(f => f);

        for (const configPath of pleskFiles) {
          const siteInfo = await this.parseNginxConfig(configPath, true);
          if (siteInfo) {
            sites.push({ ...siteInfo, configPath: configPath + ' (Plesk)' });
          }
        }
      } catch (err) {
        console.error('Error reading Plesk conf.d:', err);
      }
    } catch (error) {
      console.error('Error getting nginx sites:', error);
    }

    return sites;
  }

  private async parseNginxConfig(configPath: string, isEnabled: boolean): Promise<{ domain: string; configPath: string; isEnabled: boolean; port: number; isSsl: boolean; sslCertPath?: string } | null> {
    try {
      // Use sudo for Plesk configs (they're owned by root)
      let content: string;
      if (configPath.includes('/var/www/vhosts/system') || configPath.includes('/etc/nginx/plesk.conf.d')) {
        const { stdout } = await execAsync(`sudo cat "${configPath}"`);
        content = stdout;
      } else {
        content = await fs.readFile(configPath, 'utf-8');
      }
      
      // Extract server_name
      const serverNameMatch = content.match(/server_name\s+([^;]+);/);
      if (!serverNameMatch) return null;
      
      const domains = serverNameMatch[1].trim().split(/\s+/);
      const domain = domains.find(d => d !== '_') || domains[0];
      
      // Check for SSL first
      const hasSslCert = content.includes('ssl_certificate');
      
      // Extract listen port and SSL
      // Look for all listen directives (supports both "listen 443 ssl" and "listen IP:443 ssl" formats)
      const listenMatches = content.matchAll(/listen\s+(?:[\d.]+:)?(\d+)(?:\s+ssl)?/g);
      let port = 80;
      let isSsl = hasSslCert;
      
      for (const match of listenMatches) {
        const matchedPort = parseInt(match[1]);
        const hasSslFlag = match[0].includes(' ssl');
        
        // Prefer SSL port if available
        if (hasSslFlag || matchedPort === 443) {
          port = matchedPort;
          isSsl = true;
          break;
        } else if (port === 80) {
          port = matchedPort;
        }
      }
      
      // If ssl_certificate is present but no explicit SSL listen, assume 443
      if (hasSslCert && !isSsl) {
        port = 443;
        isSsl = true;
      }
      
      // Extract SSL certificate path
      let sslCertPath: string | undefined;
      if (isSsl) {
        const certMatch = content.match(/ssl_certificate\s+([^;]+);/);
        if (certMatch) {
          sslCertPath = certMatch[1].trim();
        }
      }

      return {
        domain,
        configPath,
        isEnabled,
        port,
        isSsl,
        sslCertPath,
      };
    } catch (error) {
      console.error(`Error parsing nginx config ${configPath}:`, error);
      return null;
    }
  }

  private async checkSite(site: { domain: string; configPath: string; isEnabled: boolean; port: number; isSsl: boolean; sslCertPath?: string }): Promise<Site> {
    const result: Site = {
      domain: site.domain,
      configPath: site.configPath,
      isEnabled: site.isEnabled,
      port: site.port,
      isSsl: site.isSsl,
      sslCertPath: site.sslCertPath,
      isReachable: false,
    };

    // Check SSL certificate expiry if SSL
    if (site.isSsl && site.sslCertPath) {
      try {
        // For Plesk certs, read directly from disk (much faster and more reliable)
        if (site.sslCertPath.startsWith('/opt/psa/var/certificates/')) {
          const certInfo = await this.getPleskSSLCertInfo(site.sslCertPath);
          if (certInfo) {
            result.sslCertExpiry = certInfo.expiry;
            result.sslDaysRemaining = certInfo.daysRemaining;
          } else {
            console.log(`⚠️  SSL cert check failed for ${site.domain}:${site.port}`);
          }
        } else {
          // For non-Plesk certs, use network check
          const certInfo = await this.getSSLCertInfo(site.domain, site.port);
          if (certInfo) {
            result.sslCertExpiry = certInfo.expiry;
            result.sslDaysRemaining = certInfo.daysRemaining;
          } else {
            console.log(`⚠️  SSL cert check failed for ${site.domain}:${site.port}`);
          }
        }
      } catch (err) {
        console.error(`❌ Error getting SSL cert for ${site.domain}:`, err);
      }
    }

    // Check if site is reachable
    try {
      const reachability = await this.checkReachability(site.domain, site.port, site.isSsl);
      result.isReachable = reachability.isReachable;
      result.httpStatusCode = reachability.statusCode;
      result.responseTimeMs = reachability.responseTime;
      
      if (!reachability.isReachable) {
        console.log(`⚠️  Reachability check failed for ${site.domain}:${site.port}`);
      }
    } catch (err) {
      console.error(`❌ Error checking reachability for ${site.domain}:`, err);
    }

    return result;
  }

  private async getPleskSSLCertInfo(certPath: string): Promise<{ expiry: Date; daysRemaining: number } | null> {
    try {
      // Use openssl to read certificate expiry date from file
      const { stdout } = await execAsync(`sudo openssl x509 -noout -enddate -in "${certPath}" 2>/dev/null`);
      const endDateMatch = stdout.match(/notAfter=(.+)/);
      
      if (endDateMatch) {
        const expiry = new Date(endDateMatch[1]);
        const now = new Date();
        const daysRemaining = Math.floor((expiry.getTime() - now.getTime()) / (1000 * 60 * 60 * 24));
        return { expiry, daysRemaining };
      }
      
      return null;
    } catch (err) {
      return null;
    }
  }

  private async getSSLCertInfo(domain: string, port: number): Promise<{ expiry: Date; daysRemaining: number } | null> {
    return new Promise((resolve) => {
      const options = {
        host: domain,
        port: port,
        method: 'GET',
        rejectUnauthorized: false,
        servername: domain, // SNI support for virtual hosts
        family: 4, // Force IPv4
      };

      const req = https.request(options, (res) => {
        const cert = (res.socket as tls.TLSSocket).getPeerCertificate();
        if (cert && cert.valid_to) {
          const expiry = new Date(cert.valid_to);
          const now = new Date();
          const daysRemaining = Math.floor((expiry.getTime() - now.getTime()) / (1000 * 60 * 60 * 24));
          resolve({ expiry, daysRemaining });
        } else {
          resolve(null);
        }
      });

      req.on('error', (err) => {
        console.log(`SSL check error for ${domain}:${port} - ${err.message}`);
        resolve(null);
      });
      req.setTimeout(20000, () => {
        req.destroy();
        resolve(null);
      });
      req.end();
    });
  }

  private async checkReachability(domain: string, port: number, isSsl: boolean): Promise<{ isReachable: boolean; statusCode?: number; responseTime?: number }> {
    return new Promise((resolve) => {
      const startTime = Date.now();
      const protocol = isSsl ? https : http;
      // Don't include port in URL if it's standard (80/443)
      const isStandardPort = (isSsl && port === 443) || (!isSsl && port === 80);
      const url = isStandardPort 
        ? `${isSsl ? 'https' : 'http'}://${domain}`
        : `${isSsl ? 'https' : 'http'}://${domain}:${port}`;

      const options: any = {
        rejectUnauthorized: false,
        family: 4, // Force IPv4
        headers: {
          'User-Agent': 'Server-Monitor-Agent/1.0',
        },
      };

      if (isSsl) {
        options.servername = domain; // SNI support
      }

      const req = protocol.get(url, options, (res) => {
        const responseTime = Date.now() - startTime;
        resolve({
          isReachable: true,
          statusCode: res.statusCode,
          responseTime,
        });
        req.destroy();
      });

      req.on('error', (err) => {
        console.log(`Reachability check error for ${domain}:${port} - ${err.message}`);
        resolve({ isReachable: false });
      });

      req.setTimeout(10000, () => {
        req.destroy();
        resolve({ isReachable: false });
      });
    });
  }

  private async pathExists(path: string): Promise<boolean> {
    try {
      await fs.access(path);
      return true;
    } catch {
      return false;
    }
  }
}
