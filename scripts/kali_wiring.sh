#!/usr/bin/env bash
# Kali-side wiring for ad-lite-lab (run ON Kali, needs sudo).
# Maps the DC name to the host-gateway IP and points krb5 at it explicitly.
set -euo pipefail
GW=$(getent hosts host.docker.internal | awk '{print $1; exit}')
[ -n "$GW" ] || { echo "cannot resolve host.docker.internal" >&2; exit 1; }

if ! grep -q "dc01.lite.corp" /etc/hosts; then
  echo "$GW dc01.lite.corp dc01 lite.corp" | sudo tee -a /etc/hosts
  echo "hosts entry added -> $GW"
else
  echo "hosts entry already present"
fi

if [ ! -f /etc/krb5.conf.d/99-lite-corp ]; then
  sudo mkdir -p /etc/krb5.conf.d
  sudo tee /etc/krb5.conf.d/99-lite-corp >/dev/null <<'EOF'
[realms]
    LITE.CORP = {
        kdc = dc01.lite.corp
        admin_server = dc01.lite.corp
    }
[domain_realm]
    .lite.corp = LITE.CORP
    lite.corp = LITE.CORP
EOF
  echo "krb5 realm fragment installed"
else
  echo "krb5 fragment already present"
fi
# PITFALL(2026-11-04实测): stock Kali /etc/krb5.conf has NO 'includedir
# /etc/krb5.conf.d' line, so the fragment alone is never read and kinit
# fails 'Cannot find KDC for realm'. Append to the MAIN file as well.
if ! sudo grep -q "LITE.CORP" /etc/krb5.conf; then
  sudo tee -a /etc/krb5.conf >/dev/null <<'EOF'

[realms]
    LITE.CORP = {
        kdc = dc01.lite.corp
        admin_server = dc01.lite.corp
    }
[domain_realm]
    .lite.corp = LITE.CORP
    lite.corp = LITE.CORP
EOF
  echo "krb5 realm appended to /etc/krb5.conf"
else
  echo "krb5 main conf already has LITE.CORP"
fi
echo "Kali wiring done (DC = $GW)"
