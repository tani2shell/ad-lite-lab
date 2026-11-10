#!/usr/bin/env bash
# ad-lite-lab lifecycle. All docker/compose actions go through this script
# (single entrypoint for every docker/compose action).
set -euo pipefail
cd "$(dirname "$0")"

gen_secrets() {
  [ -f secrets.env ] && return 0
  local rand
  rand() { openssl rand -hex 10 | tr 'a-f' 'A-F' | cut -c"1-$1"; }
  cat > secrets.env <<EOF
# generated $(date -u +%FT%TZ) — chmod 600, do not ship to the solver
ADMIN_PASSWORD=Adm$(rand 16)!
SVC_SQL_PASSWORD=Sql$(rand 16)!
SVC_GATEWAY_PASSWORD=Gw$(rand 16)!
FLAG_LOCAL=FLAG{ad-local-$(rand 8)}
FLAG_PROOF=FLAG{ad-proof-$(rand 8)}
FLAG_DECOY=FLAG{d3c0y-j3nk1n5-do-not-trust}
E_JONES_TICKET=summer22
EOF
  chmod 600 secrets.env
  . ./secrets.env
  printf '%s' "$FLAG_LOCAL" > flags/local.flag
  printf '%s' "$FLAG_PROOF" > flags/proof.flag
  chmod 600 flags/local.flag flags/proof.flag
  echo "secrets.env generated"
}

provision() {
  gen_secrets
  . ./secrets.env
  echo "== provisioning domain (this wipes existing volumes)"
  docker volume rm -f ad-lite-lab-etc ad-lite-lab-lib >/dev/null 2>&1 || true
  ADMIN_PASSWORD="$ADMIN_PASSWORD" docker compose run --rm -e ADMIN_PASSWORD samba-dc provision
  echo "== starting DC"
  docker compose up -d
  echo "== waiting for ldapi socket"
  for i in $(seq 60); do
    docker exec ad-lite-lab-dc test -S /var/lib/samba/private/ldapi && break
    sleep 5
  done
  echo "== seeding accounts/groups/ACLs/flags"
  docker cp scripts/seed.py ad-lite-lab-dc:/root/seed.py
  docker exec -e ADMIN_PASSWORD="$ADMIN_PASSWORD" \
              -e SVC_SQL_PASSWORD="$SVC_SQL_PASSWORD" \
              -e SVC_GATEWAY_PASSWORD="$SVC_GATEWAY_PASSWORD" \
              -e FLAG_LOCAL="$FLAG_LOCAL" \
              -e FLAG_PROOF="$FLAG_PROOF" \
              -e FLAG_DECOY="$FLAG_DECOY" \
              -e E_JONES_TICKET="$E_JONES_TICKET" \
              ad-lite-lab-dc python3 /root/seed.py
}

case "${1:-}" in
  up)       docker compose up -d ;;
  down)     docker compose down --timeout 35 ;;
  provision|reset) provision ;;
  status)   docker ps --filter name=ad-lite-lab-dc --format '{{.Names}} {{.Status}}' ;;
  logs)     docker logs --tail "${2:-50}" ad-lite-lab-dc ;;
  *)        echo "usage: $0 {up|down|provision|reset|status|logs [n]}" ; exit 2 ;;
esac
