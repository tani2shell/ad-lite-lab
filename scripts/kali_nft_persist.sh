#!/usr/bin/env bash
# forge t_c9abdd27: persist lite-nat/lite-filter nft rules across reboots (root cause of
# 2026-11-08 UDP:88 shadow-stub incident — rules were live-added only, lost on Kali reboot)
set -eu
sudo -n tee /etc/systemd/system/lite-kdc-nft.service >/dev/null <<'EOF'
[Unit]
Description=ad-lite-lab nft KDC redirect rules (persist across reboot)
After=network-online.target
Wants=network-online.target

[Service]
Type=oneshot
RemainAfterExit=yes
ExecStartPre=/usr/sbin/nft delete table ip lite-nat if exists
ExecStartPre=/usr/sbin/nft delete table ip lite-filter if exists
ExecStart=/usr/sbin/nft add table ip lite-nat
ExecStart=/usr/sbin/nft 'add chain ip lite-nat output { type nat hook output priority -100; }'
ExecStart=/usr/sbin/nft add rule ip lite-nat output meta l4proto tcp tcp dport 88 redirect to :1888
ExecStart=/usr/sbin/nft add table ip lite-filter
ExecStart=/usr/sbin/nft 'add chain ip lite-filter output { type filter hook output priority 0; }'
ExecStart=/usr/sbin/nft add rule ip lite-filter output meta l4proto udp udp dport 88 reject with icmp port-unreachable

[Install]
WantedBy=multi-user.target
EOF
sudo -n systemctl daemon-reload
sudo -n systemctl enable lite-kdc-nft.service
# apply live now (same guarded sequence)
sudo -n nft delete table ip lite-nat if exists 2>/dev/null || true
sudo -n nft delete table ip lite-filter if exists 2>/dev/null || true
sudo -n nft add table ip lite-nat
sudo -n nft 'add chain ip lite-nat output { type nat hook output priority -100; }'
sudo -n nft add rule ip lite-nat output meta l4proto tcp tcp dport 88 redirect to :1888
sudo -n nft add table ip lite-filter
sudo -n nft 'add chain ip lite-filter output { type filter hook output priority 0; }'
sudo -n nft add rule ip lite-filter output meta l4proto udp udp dport 88 reject with icmp port-unreachable
echo "-- state --"
systemctl is-enabled lite-kdc-nft lite-kdc-relay
sudo -n nft list tables
sudo -n nft list table ip lite-nat | grep redirect
sudo -n nft list table ip lite-filter | grep reject
