#!/usr/bin/env bash
# Re-run seed (idempotent) with the enctypes fix + drop the bogus conf.d drop-in
set -euo pipefail
cd "$(dirname "$0")/.."
# conf.d/60-krb5-weak.conf = domain enctypes fix (CVE-2026-20833 AES-only flip), KEEP.
# Ensure SMB shares allow anonymous read (SYSVOL notes.txt hunt):
docker cp scripts/ensure_guest_ok.py ad-lite-lab-dc:/tmp/ && docker exec ad-lite-lab-dc python3 /tmp/ensure_guest_ok.py
# seed.py short-circuits on /root/.seed.done — must clear for re-apply
docker exec ad-lite-lab-dc rm -f /root/.seed.done
set -a; . ./secrets.env; set +a
docker cp scripts/seed.py ad-lite-lab-dc:/root/seed.py
docker exec -e ADMIN_PASSWORD -e SVC_SQL_PASSWORD -e SVC_GATEWAY_PASSWORD \
            -e FLAG_LOCAL -e FLAG_PROOF -e FLAG_DECOY -e E_JONES_TICKET \
            ad-lite-lab-dc python3 /root/seed.py 2>&1 | tail -8
