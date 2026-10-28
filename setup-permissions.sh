#!/bin/bash
#
# setup-permissions.sh — GEHARDENDE versie (monitoring-agent)
# Configureert minimale, veilige passwordless-sudo voor de monitoring-agent.
#
# Verschil met de oude versie:
#  - GEEN brede wildcards meer (geen `tail /var/log/*`, `grep * /var/log/auth.log`,
#    `cat ... plesk ...`) die willekeurige bestanden als root laten lezen.
#  - Alleen commando's die ECHT root vereisen, met VASTE paden.
#  - De agent leest de rest direct (lid van groep `adm`): nginx-logs, systemd-journal,
#    sites-enabled, /home. (Vereist de bijbehorende agent-code-update.)
#
# Gebruik (als de agent-user, NIET als root):
#   ./setup-permissions.sh [agent-user]     # default: huidige $USER

set -euo pipefail

AGENT_USER="${1:-$USER}"
SUDOERS_FILE="/etc/sudoers.d/monitoring-agent"

G='\033[0;32m'; Y='\033[1;33m'; R='\033[0;31m'; N='\033[0m'
echo -e "${G}=== Monitoring Agent - setup (hardened) ===${N}"

if [ "$(id -u)" -eq 0 ]; then
  echo -e "${R}Niet als root draaien. Draai als de agent-user (bijv. ./setup-permissions.sh agentuser)${N}"; exit 1
fi

echo -e "${Y}Dit script:${N}"
echo "  1. Voegt '$AGENT_USER' toe aan groep 'adm' (voor sudoloze log-/journal-reads)"
echo "  2. Schrijft een MINIMALE sudoers naar $SUDOERS_FILE (gevalideerd met visudo)"
echo "  3. Maakt eerst een back-up van een bestaand bestand"
read -p "Doorgaan? (y/n) " -n 1 -r; echo
[[ $REPLY =~ ^[Yy]$ ]] || { echo "Geannuleerd."; exit 1; }

# --- Stap 1: adm-groep -------------------------------------------------------
echo -e "${G}Stap 1: '$AGENT_USER' toevoegen aan groep 'adm'...${N}"
sudo usermod -aG adm "$AGENT_USER"

# --- Stap 2: sudoers opbouwen in temp ---------------------------------------
echo -e "${G}Stap 2: minimale sudoers opbouwen...${N}"
TMP="$(mktemp)"
{
  echo "# Monitoring Agent - minimal passwordless sudo (hardened $(date))"
  echo "# Alleen root-vereiste commando's, VASTE paden, GEEN misbruikbare wildcards."
  echo ""
  echo "# Firewall-status"
  echo "$AGENT_USER ALL=(ALL) NOPASSWD: /usr/sbin/ufw status"
  echo "$AGENT_USER ALL=(ALL) NOPASSWD: /usr/sbin/iptables -L -n"
  echo ""
  echo "# fail2ban: ALLEEN status (geen set/unban/reload)"
  echo "$AGENT_USER ALL=(ALL) NOPASSWD: /usr/bin/fail2ban-client status"
  echo "$AGENT_USER ALL=(ALL) NOPASSWD: /usr/bin/fail2ban-client status *"
  echo ""
  echo "# SSL-einddatum (cert-mappen; openssl x509 lekt geen niet-cert inhoud)"
  echo "$AGENT_USER ALL=(ALL) NOPASSWD: /usr/bin/openssl x509 -noout -enddate -in /etc/letsencrypt/*"
  echo "$AGENT_USER ALL=(ALL) NOPASSWD: /usr/bin/openssl x509 -noout -enddate -in /etc/ssl/*"
  echo ""
  echo "# php-fpm/php error-logs (root:root 600) - alleen bestaande, VASTE paden"
  shopt -s nullglob
  for log in /var/log/php*-fpm.log /var/log/php-fpm/error.log /var/log/php/error.log; do
    [ -f "$log" ] && echo "$AGENT_USER ALL=(ALL) NOPASSWD: /usr/bin/tail -[0-9]* $log"
  done
  shopt -u nullglob
} > "$TMP"

# --- Stap 3: valideren + atomair installeren --------------------------------
echo -e "${G}Stap 3: valideren met visudo...${N}"
if sudo visudo -cf "$TMP"; then
  if [ -f "$SUDOERS_FILE" ]; then
    BK="${SUDOERS_FILE}.bak-$(date +%F-%H%M%S)"
    sudo cp -a "$SUDOERS_FILE" "$BK"
    echo -e "${Y}Back-up van oude versie: $BK${N}"
  fi
  sudo install -m 0440 -o root -g root "$TMP" "$SUDOERS_FILE"
  rm -f "$TMP"
  echo -e "${G}✓ $SUDOERS_FILE geïnstalleerd en gevalideerd${N}"
else
  rm -f "$TMP"
  echo -e "${R}✗ Validatie faalde — niets gewijzigd aan $SUDOERS_FILE${N}"; exit 1
fi

# --- Stap 4: hele sudoers-set nog eens valideren ----------------------------
sudo visudo -c >/dev/null && echo -e "${G}✓ Volledige sudoers-set is geldig${N}"

echo ""
echo -e "${G}=== Klaar ===${N}"
echo -e "${Y}Let op:${N} log uit/in (of 'newgrp adm') voor de groepswijziging."
echo "Snelle controle:"
echo "  sudo -n grep x \$SUDOERS_FILE /var/log/auth.log 2>&1 | head -1   # moet 'password is required' geven"
echo "  sudo -n ufw status | head -1                                     # moet werken"
echo ""
echo -e "${R}BELANGRIJK:${N} werk ook de agent-code bij (directe reads i.p.v. sudo) —"
echo "zie fase3-monitoring-agent-hardening.md. Tot die tijd missen sommige collectors data."
