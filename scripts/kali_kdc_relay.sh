#!/usr/bin/env bash
# ad-lite-lab Kali wiring v2: transparent KDC redirect.
# macOS on the range host shadows TCP/UDP :88 (File Sharing kdc) and :445 (smbd);
# the DC mirror ports are host 1088/1445 (compose). On Kali we REDIRECT
# anything addressed to *:88 into a local relay that speaks to the mirror, so
# every AD tool keeps its default port and -dc-ip 0.250.250.254 posture.
# SMB has no such trick: SMB tools must use -p/--port 1445.
set -euo pipefail

command -v socat >/dev/null || sudo -n apt-get install -y socat

sudo -n tee /etc/systemd/system/lite-kdc-relay.service >/dev/null <<'EOF'
[Unit]
Description=ad-lite-lab KDC relay (local 1888 -> DC mirror 1088)
After=network-online.target

[Service]
ExecStart=/usr/bin/socat TCP-LISTEN:1888,fork,reuseaddr TCP:dc01.lite.corp:1088
Restart=always
User=nobody

[Install]
WantedBy=multi-user.target
EOF
sudo -n systemctl daemon-reload
sudo -n systemctl enable lite-kdc-relay
sudo -n systemctl restart lite-kdc-relay || sudo -n systemctl start lite-kdc-relay

# redirect TCP 88 -> relay; kill UDP 88 so clients fall back to TCP (nft-native)
if ! sudo -n nft list table ip lite-nat >/dev/null 2>&1; then
  sudo -n nft add table ip lite-nat
  sudo -n nft 'add chain ip lite-nat output { type nat hook output priority -100; }'
  sudo -n nft add rule ip lite-nat output meta l4proto tcp tcp dport 88 redirect to :1888
fi
if ! sudo -n nft list table ip lite-filter >/dev/null 2>&1; then
  sudo -n nft add table ip lite-filter
  sudo -n nft 'add chain ip lite-filter output { type filter hook output priority 0; }'
  sudo -n nft add rule ip lite-filter output meta l4proto udp udp dport 88 reject with icmp port-unreachable
fi

# krb5: standard hostname/port (iptables does the magic)
if sudo -n grep -q "# --- LITE.CORP ---" /etc/krb5.conf; then
  sudo -n python3 - <<'PYEOF'
import re
p="/etc/krb5.conf"; s=open(p).read()
s=re.sub(r"\n# --- LITE\.CORP ---$.*$","\n",s,flags=re.S)
s+="""
# --- LITE.CORP ---
[realms]
    LITE.CORP = {
        kdc = dc01.lite.corp
        admin_server = dc01.lite.corp
    }
[domain_realm]
    .lite.corp = LITE.CORP
    lite.corp = LITE.CORP
"""
open(p,"w").write(s)
PYEOF
fi
sudo -n tee /etc/krb5.conf.d/99-lite-corp >/dev/null <<'EOF'
[realms]
    LITE.CORP = {
        kdc = dc01.lite.corp
        admin_server = dc01.lite.corp
    }
[domain_realm]
    .lite.corp = LITE.CORP
    lite.corp = LITE.CORP
EOF

echo "relay: $(systemctl is-active lite-kdc-relay)"
sudo -n nft list tables
sudo -n nft list table ip lite-nat
kdestroy 2>/dev/null || true
echo Qwerty123 | timeout 12 kinit -V aops@LITE.CORP 2>&1 | tail -1
