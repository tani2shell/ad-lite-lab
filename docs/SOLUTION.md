# ad-lite-lab — intended solution (SPOILERS)

Open only after solving (or after you decide you want the route).
Valid for builds anchored to base-image digest `sha256:d46275b4…`; default
seed flags verify at `sha8(local)=037b49ca` / `sha8(proof)=98e5106a`
(8-char hash of the generated flag files — yours will differ if you changed
`secrets.env`).

## The map

- Domain `LITE.CORP` / NetBIOS `LITE`, one DC `dc01.lite.corp`.
- Both flags are values of a **custom confidential LDAP attribute**
  `msLite-Flag` (own schema class, OID `1.2.840.113556.1.4.99999.1`,
  `systemFlags=4` = ATTRIBUTE_IS_CONFIDENTIAL, plus
  `showInAdvancedViewOnly` belt-and-braces):
  - `local.flag` → on `svc_gateway`
  - `proof.flag` → on the DC machine account `DC01$`
- Confidential attributes are invisible to ordinary binds — even the
  *attribute name* doesn't render. Only a holder of replication rights can
  see them. That is the lab's final lesson.

## Intended chain

1. **Fish anonymously.** SMB guest access (port 445 / macOS mirror 1445)
   exposes `SYSVOL`/`NETLOGON` with a `notes.txt`: a decoy token
   (`FLAG{d3c0y-j3nk1n5-do-not-trust}` — looks like a flag, scores zero),
   a retired-SPN hint, and a "Tier-2-Operators retirement plan" tease.
2. **Enter through the weak door.** `OU=Staff` user `e.jones` carries a
   season-theme password that is a byte-exact member of common top-50k
   wordlists (default build: rank ≈19.6k in a top-50k list; blind spray
   entry measured at ≈117.9k requests in a 6-wide spray, ≈19.6k single-user).
   Its description line ("IT ticket #4411: Tier-2-Operators ownership
   handover pending") is the breadcrumb toward the ACL surface.
   `kinit e.jones@LITE.CORP` → first TGT.
3. **Eyes open after auth.** Authenticated LDAP bind bypasses the anonymous
   wall (`00002020`). Enumeration shows `e.jones` holds **GenericAll**
   (full mask, incl. WriteMembers) on `CN=Tier-2-Operators` and on
   `svc_gateway`. (You will *not* find this by reading your own
   `nTSecurityDescriptor` — SD invisibility is by design; the breadcrumb +
   full authenticated enumeration is the intended discovery path.)
4. **Join the group.** `ldapmodify` adds yourself to Tier-2-Operators.
5. **Read the invisible.** Tier-2-Operators holds DCSync extended rights
   (Get-Changes `1131f6aa` + Get-Changes-All `1131f6ad`) at the domain root.
   On Windows you'd DCSync; **on this Samba build the replication surface
   returns no entries** (measured wall) — the field-proven solve is one
   OID-indexed query that harvests both flags at once:

   ```bash
   ldapsearch -x -b DC=lite,DC=corp \
     '(&(objectClass=*)(1.2.840.113556.1.4.99999.1=*))' msLite-Flag
   ```

## Alternate routes (verified to work)

- **Force-Change-Password bonus:** Tier-2-Operators also holds
  `User-Force-Change-Password` (`91cdb660`) domain-wide — reset anything,
  walk to Domain Admin in 1–2 steps. A deliberately left bonus flaw.
- **Kerberoast:** `svc_sql` (MSSQLSvc SPN, `msDS-supportedEncryptionTypes=24`
  → AES, hashcat 18200/19900). impacket's default request path hits the
  `KRB_AP_ERR_INAPP_CKSUM` interop wall; `-request` routes around it.
- **AS-REP:** `aops` has `DONT_REQ_PREAUTH` but `msDS=0` — and the hardened
  4.24 KDC returns no hash anyway (see walls). Decorative.
- **Constrained-delegation decoy:** `svc_backup` is
  TRUSTED_FOR_DELEGATION with an HTTP/backupsrv SPN and a weak
  `Backup2019!`-family password — not on the intended chain.
- **Golden ticket:** the `cifs/dc01.lite.corp` SPN is registered in-seed
  (Samba doesn't register cifs natively; without this fix, golden-ticket →
  SMB replay dies and a whole teaching branch silently vanishes).

## Walls that are BY DESIGN (don't debug them away)

1. **Anonymous LDAP bind refused** (`00002020`) — Kerberos error taxonomy
   (`PREAUTH_REQUIRED` = exists vs `PRINCIPAL_UNKNOWN` = doesn't) is the
   only live anonymous enumeration path.
2. **Host port shadows on macOS** — SMB via `--port 1445`; netexec must use
   `--port` (its `-p` is *password*).
3. **Kerberos relay** `88 → 1888 → host:1088` (see README platform matrix).
4. **bloodyAD v2 paged-search control** (`1.2.840.113556.1.4.2065`) is
   rejected by Samba as a critical unregistered control — fall back to
   native `ldapsearch` paging.
5. **AS-REP roasting yields no hash on Samba 4.24** even with
   `DONT_REQ_PREAUTH` set (UAC `66048` live-verified).
6. **impacket Kerberoast request path** → `KRB_AP_ERR_INAPP_CKSUM`
   (measured on 4.24); the enumeration half still works.
7. **DCSync surfaces nothing** for confidential attributes on this Samba —
   if your dump is empty, you're exactly where the lab wants you (→ step 5).
8. **LDAP simple bind is UPN-only on Samba 4.24** — `DOMAIN\user` and the
   bare `user` fail `49/52e` with *correct* passwords while the same
   credentials pass over SMB and Kerberos. Do not conclude "account locked"
   from LDAP alone; retry as `user@LITE.CORP`.
9. **`unicodePwd` writes demand LDAPS** — plaintext `389` modify fails
   `WILL_NOT_PERFORM (0000001F / data 5003)`. Use `ldaps://…:636` with
   `LDAPTLS_REQCERT=never` (self-signed cert). `636`/`464` are published in
   compose. (Verified live by the n=1 black-box run, which rotated
   `svc_gateway`'s password over 636 and read the flags as that account.)

## Dictionary accounting (calibrate your own runs before blaming the target)

- The entry password is a byte-exact (`grep -Fx`) member of mainstream
  top-50k and rockyou wordlists — a run that "misses" it has a tooling
  problem.
- Famous false-negative, learned the hard way: `kinit` fed a password via
  stdin prints `Password for <principal>: ` to **stderr even on success**.
  Any hit-gate that captures stderr and demands *empty output* will
  structurally swallow every true hit. Gate on exit code (`rc==0`) only,
  and re-confirm candidates with serial single-shot `kinit`.
