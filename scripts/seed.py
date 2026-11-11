#!/usr/bin/env python3
"""ad-lite-lab seed: OUs, accounts, groups, SPNs, ACL chain, confidential
flag attributes, decoys. Run inside the DC container as root (ldapi/SYSTEM).
Idempotent via /root/.seed marker + per-object existence checks."""
import os
import re
import subprocess
import sys
import time

import ldb
from samba.auth import system_session
from ldb import LdbError
from samba.credentials import Credentials
from samba.dcerpc import security
from samba.ndr import ndr_pack, ndr_unpack
from samba.param import LoadParm
from samba.samdb import SamDB

MARKER = "/root/.seed.done"
ENV = os.environ

def log(msg):
    print(f"[seed] {msg}", flush=True)

def conn(max_wait=90):
    """Bind as built-in Administrator (we hold the password): full rights
    including schema-partition writes, which SYSTEM over ldapi lacks.
    Retries: reseed's ensure_guest_ok.py restarts samba right before seed.py
    runs and the ldapi socket needs seconds to come back (2026-11-10 race:
    NT_STATUS_UNSUCCESSFUL on the first post-restart connect)."""
    lp = LoadParm()
    lp.load("/etc/samba/smb.conf")
    creds = Credentials()
    creds.guess(lp)
    creds.set_username("Administrator")
    creds.set_domain("LITE")
    creds.set_password(ENV["ADMIN_PASSWORD"])
    deadline = time.time() + max_wait
    while True:
        try:
            return SamDB(url="ldapi:///var/lib/samba/private/ldapi",
                         credentials=creds, lp=lp)
        except LdbError:
            if time.time() > deadline:
                raise
            time.sleep(3)

def samba_tool(*args):
    r = subprocess.run(["samba-tool"] + list(args),
                       capture_output=True, text=True)
    if r.returncode != 0:
        # "already exists" style errors are tolerated by callers
        raise RuntimeError(f"samba-tool {' '.join(args)}: {r.stderr.strip()}")
    return r.stdout

BASE_DN = None  # set in main(); SUBTREE searches need a concrete base
                # (empty base -> LDAP_NO_SUCH_OBJECT 'empty base DN' from
                # the partition router — 实测 4.24)
DOM_SID = None  # set in main(); needed for descriptor.as_sddl/from_sddl

def find(samdb, filt, attrs=("dn",)):
    # NOTE: SamDB.search C-binding takes positional args only; the filter
    # keyword is `expression`, `filter=` raises TypeError (4.24 实测).
    return samdb.search(BASE_DN, ldb.SCOPE_SUBTREE, filt, list(attrs))

def mkmsg(samdb, dn, pairs):
    m = ldb.Message()
    m.dn = ldb.Dn(samdb, dn)
    for k, v in pairs.items():
        vals = v if isinstance(v, (list, tuple)) else [v]
        m[k] = ldb.MessageElement([str(x) for x in vals],
                                  ldb.FLAG_MOD_ADD, k)
    return m

def ensure_ou(samdb, base, ou):
    dn = f"OU={ou},{base}"
    try:
        samdb.add(mkmsg(samdb, dn, {
            "objectClass": ["top", "organizationalUnit"],
            "description": "ad-lite-lab lab",
        }))
        log(f"OU created: {ou}")
    except ldb.LdbError as e:
        if e.args[0] != ldb.ERR_ENTRY_ALREADY_EXISTS:
            raise
    return dn

def sid_of(samdb, acct):
    res = samdb.search(BASE_DN, ldb.SCOPE_SUBTREE,
                       f"(sAMAccountName={acct})", ["objectSid"])
    if not res:
        raise RuntimeError(f"no such account: {acct}")
    return str(ndr_unpack(security.dom_sid, bytes(res[0]["objectSid"][0])))

def expand_ace(ace):
    """Round-trip an ACE through from_sddl/as_sddl to its canonical expanded
    form (GA is stored/printed as the full CCDCLCSWRPWPDTLOCRSDRCWDWO mask —
    a literal 'GA' substring check against stored SDDL NEVER matches)."""
    d = security.descriptor.from_sddl("D:" + ace, DOM_SID)
    return d.as_sddl(DOM_SID)[2:]

def append_dacl(samdb, dn, ace):
    """Append an ACE to the object's DACL (dedup on canonical form).
    Round-trip via the descriptor's own as_sddl/from_sddl (this ldb build
    rejects the as-SDDL search control and SamDB.search rejects the ldif
    control-string form — 实测). The ACE is inserted at the END OF THE D:
    SECTION — a naive sddl+ace would splice into the SACL when the SD
    carries an S: section."""
    want = expand_ace(ace)
    res = samdb.search(base=str(dn), scope=ldb.SCOPE_BASE,
                       attrs=["nTSecurityDescriptor"])
    desc = ndr_unpack(security.descriptor,
                      bytes(res[0]["nTSecurityDescriptor"][0]))
    sddl = desc.as_sddl(DOM_SID)
    # canonicalize existing DACL: split D section into ACE tuples, drop
    # duplicates of `want` (debug-era seeds appended repeats)
    m2 = re.search(r"(?<![A-Za-z0-9-])S[:;]", sddl)
    if m2:
        pre, sacl = sddl[:m2.start()], sddl[m2.start():]
    else:
        pre, sacl = sddl, ""
    # head = O:/G:/D: prefixes before first '(' ; split ACEs
    mi = pre.index("(")
    prefix, body = pre[:mi], pre[mi:]
    existing = re.findall(r"\((?:OA|A|OU|AU)[^)]*\)", body)
    kept, seen_dup = [], False
    for a in existing:
        a_exp = expand_ace(a)
        if a_exp == want:
            if seen_dup:
                continue          # drop extra copies
            seen_dup = True
            kept.append(a)        # keep canonical stored spelling
        else:
            kept.append(a)
    if seen_dup:
        new_sddl = prefix + "".join(kept) + sacl
        nd = security.descriptor.from_sddl(new_sddl, DOM_SID)
        m = ldb.Message()
        m.dn = ldb.Dn(samdb, str(dn))
        m["nTSecurityDescriptor"] = ldb.MessageElement(
            ndr_pack(nd), ldb.FLAG_MOD_REPLACE, "nTSecurityDescriptor")
        samdb.modify(m)
        log(f"dedup: {dn}")
        return
    new_sddl = prefix + "".join(kept) + want + sacl
    nd = security.descriptor.from_sddl(new_sddl, DOM_SID)
    m = ldb.Message()
    m.dn = ldb.Dn(samdb, str(dn))
    m["nTSecurityDescriptor"] = ldb.MessageElement(
        ndr_pack(nd), ldb.FLAG_MOD_REPLACE, "nTSecurityDescriptor")
    samdb.modify(m)
    log(f"ACE appended on {dn}")

def set_attrs(samdb, dn, pairs):
    m = ldb.Message()
    m.dn = ldb.Dn(samdb, str(dn))  # callers pass ldb.Dn or str — str() both
    for k, v in pairs.items():
        m[k] = ldb.MessageElement(str(v), ldb.FLAG_MOD_REPLACE, k)
    samdb.modify(m)
    log(f"attrs set on {dn}: {sorted(pairs)}")

# ---------------------------------------------------------------- schema
def ensure_schema(samdb, base):
    schema_base = f"CN=Schema,CN=Configuration,{base}"
    attr_dn = f"CN=ms-Lite-Flag,{schema_base}"
    cls_dn = f"CN=ms-Lite-FlagHolder,{schema_base}"
    changed = False
    try:
        samdb.add(mkmsg(samdb, attr_dn, {
            "objectClass": ["top", "attributeSchema"],
            "cn": "ms-Lite-Flag",
            "lDAPDisplayName": "msLite-Flag",
            "attributeID": "1.2.840.113556.1.4.99999.1",
            "isSingleValued": "TRUE",
            "systemOnly": "FALSE",
            "systemFlags": "4",            # ATTRIBUTE_IS_CONFIDENTIAL
            # PITFALL (2026-11-04实测): AD syntax OIDs are 2.5.5.x, NOT
            # X.500 attr types — Unicode here is 2.5.5.12 + oMSyntax 64
            # (verified against this DC's own 'description' entry; the
            # classic 2.5.5.4/19 pair is rejected as 'unknown attribute
            # syntax' 00002035).
            "attributeSyntax": "2.5.5.12",
            "oMSyntax": "64",
            "searchFlags": "0",
            "showInAdvancedViewOnly": "TRUE",
            "isMemberOfPartialAttributeSet": "FALSE",
            "adminDisplayName": "ms-Lite-Flag",
            "adminDescription": "ad-lite-lab flag attribute (confidential)",
        }))
        changed = True
        log("schema attribute msLite-Flag added")
    except ldb.LdbError as e:
        if e.args[0] != ldb.ERR_ENTRY_ALREADY_EXISTS:
            raise
        log("schema attribute msLite-Flag exists")
    for cls in ("user", "computer"):
        m = ldb.Message()
        m.dn = ldb.Dn(samdb, f"CN={cls},{schema_base}")
        m["mayContain"] = ldb.MessageElement(
            "msLite-Flag", ldb.FLAG_MOD_ADD, "mayContain")
        try:
            samdb.modify(m)
            changed = True
            log(f"msLite-Flag added to mayContain of {cls}")
        except ldb.LdbError as e:
            if "ATTRIBUTE_OR_VALUE_EXISTS" not in str(e):
                raise
            log(f"{cls} mayContain already has msLite-Flag")
    return changed

# ---------------------------------------------------------------- data
def main():
    if os.path.exists(MARKER):
        log("marker present, nothing to do")
        return
    samdb = conn()
    res = samdb.search(base="", scope=ldb.SCOPE_BASE,
                       attrs=["defaultNamingContext"])
    base = str(res[0]["defaultNamingContext"])
    log(f"domain base: {base}")
    globals()["BASE_DN"] = base
    res = samdb.search(base=base, scope=ldb.SCOPE_BASE, attrs=["objectSid"])
    globals()["DOM_SID"] = security.dom_sid(
        str(ndr_unpack(security.dom_sid, bytes(res[0]["objectSid"][0]))))
    log(f"domain sid: {DOM_SID}")

    # v2 reforge 2026-11-10: relax the lab's domain password policy
    # (small-shop realism). Default 3-of-4 complexity rejected the seed
    # entry ticket once it moved to an all-lowercase dictionary word; with
    # complexity off, every seed/reseed password is deterministic.
    samba_tool("domain", "passwordsettings", "set", "--complexity=off",
               "--min-pwd-length=6", "--min-pwd-age=0")
    log("domain password policy relaxed (complexity off, min len 6)")

    del samdb
    samdb = conn()
    changed = ensure_schema(samdb, base)
    if changed:
        log("restarting samba to load the new schema")
        subprocess.run(["supervisorctl", "restart", "samba"], check=True)
        time.sleep(5)
        samdb = None
        for _ in range(60):
            try:
                samdb = conn()
                break
            except Exception:
                time.sleep(3)
        if samdb is None:
            raise RuntimeError("samba did not come back after schema change")

    ou_staff = ensure_ou(samdb, base, "Staff")
    ou_svc = ensure_ou(samdb, base, "Services")

    # --- users (weak entry + roastables + takeover target + decoy) ------
    users = [
        # (account, password, userou, description)
        # v2 reforge 2026-11-10 (坑录⑥): entry ticket must be reachable by a
        # blind top50k spray. summer22 is a byte-exact line in Kali's
        # ~/wordlists/top50k.txt (grep -Fx verified at reseed time).
        ("e.jones", ENV["E_JONES_TICKET"], "OU=Staff",
         "IT ticket #4411: Tier-2-Operators ownership handover pending"),
        ("aops", "Qwerty123", "OU=Staff",
         "monitoring account (legacy app, do not delete)"),
        ("svc_backup", "Backup2019!", "OU=Services",
         "backup service creds rotated 2019; delegation approved in IT ticket #4402"),
        ("svc_sql", ENV["SVC_SQL_PASSWORD"], "OU=Services",
         "mssql service account"),
        ("svc_gateway", ENV["SVC_GATEWAY_PASSWORD"], "OU=Services",
         "api gateway service account"),
        ("svc_jenkins", "Jenkins2019!", "OU=Services",
         f"TODO rotate: {ENV['FLAG_DECOY']}"),
    ]
    for acct, pw, ou, desc in users:
        try:
            samba_tool("user", "create", acct, pw, f"--description={desc}",
                       f"--userou={ou}")
            log(f"user created: {acct}")
        except RuntimeError as e:
            if "already exists" in str(e):
                log(f"user exists: {acct}")
            else:
                raise

    # v2 reforge 2026-11-10: `user create` silently skips EXISTING accounts,
    # so a changed entry ticket would never apply on a reseed over surviving
    # volumes. Force-rotate it every seed (admin bind, loopback; note
    # setpassword has NO -p option — creds go as -U DOMAIN/user%pass).
    samba_tool("user", "setpassword", "e.jones",
               f"--newpassword={ENV['E_JONES_TICKET']}",
               "-U", f"LITE/Administrator%{ENV['ADMIN_PASSWORD']}")
    log("entry ticket rotated for e.jones")

    # Reset completeness: the solution path itself writes state —
    # WriteDacl->unicodePwd changes svc_gateway's password, and the ADD_SELF
    # step puts e.jones into Tier-2-Operators. `user create` skips existing
    # accounts, so both survive a plain reseed. The seed must force-restore
    # EVERY attribute the solution path writes (verified after a full solve;
    # samba-tool 4.24 syntax is 'group removemembers', rc=0 even when absent).
    samba_tool("user", "setpassword", "svc_gateway",
               f"--newpassword={ENV['SVC_GATEWAY_PASSWORD']}",
               "-U", f"LITE/Administrator%{ENV['ADMIN_PASSWORD']}")
    log("svc_gateway password rotated to factory value")
    samba_tool("group", "removemembers", "Tier-2-Operators", "e.jones")
    log("e.jones removed from Tier-2-Operators if present")

    # --- group + SPNs ----------------------------------------------------
    try:
        samba_tool("group", "create", "Tier-2-Operators",
                   "--description=second-line ops group (handover in progress)")
        log("group created: Tier-2-Operators")
    except RuntimeError as e:
        if "already exists" not in str(e):
            raise
        log("group exists: Tier-2-Operators")
    for spn, acct in (("HTTP/backupsrv.lite.corp", "svc_backup"),
                      ("MSSQLSvc/mssql01.lite.corp:1433", "svc_sql"),
                      # FIDELITY 2026-11-08 (retro t_c9abdd27 item-4): Windows DCs
                      # register cifs/<fqdn>; Samba does NOT -> GT/Golden-Ticket
                      # routes to cifs/dc01 die with kvno=0/KRB_AP_ERR_NOT_US on
                      # every Samba4 AD target. Registering it restores Windows
                      # fidelity and keeps the GT->SMB path testable.
                      ("cifs/dc01.lite.corp", "DC01$")):
        try:
            samba_tool("spn", "add", spn, acct)
            log(f"SPN added: {spn} -> {acct}")
        except RuntimeError as e:
            # samba-tool's duplicate-SPN wording varies by path: 'already
            # contains' / 'already exists' / 'already affected to another
            # user' (even for the SAME user — 实测 4.24). Tolerate 'already'.
            if "already" in str(e).lower():
                log(f"SPN exists: {spn}")
            else:
                raise

    # --- account flags: AS-REP / delegation / no-expiry / RC4 ----------
    jones_sid = sid_of(samdb, "e.jones")
    t2_sid = sid_of(samdb, "Tier-2-Operators")
    uac = {
        # v2 reforge: ticket account gets DONT_EXPIRE too (long-lived
        # instances outlived 90d max-age would silently brick the entry).
        "e.jones": 66048,  # NORMAL|DONT_EXPIRE
        # NORMAL(512) + DONT_EXPIRE(65536) + DONT_REQ_PREAUTH(4194304)
        # PITFALL 2026-11-04: per MS-ADTS (and impacket's constant),
        # UF_DONT_REQUIRE_PREAUTH = 0x400000 = 4194304. An intermediate
        # "fix" that swapped it to 262144 (=UF_SMARTCARD_REQUIRED) broke
        # AS-REP instead of fixing it. The real AS-REP/TGS breakage was the
        # msDS=24 client pin below, not this value.
        "aops": 4260480,  # NORMAL|DONT_EXPIRE|DONT_REQ_PREAUTH(0x400000)|PLAINTEXT_SAFE(0x80)
        # NORMAL + TRUSTED_FOR_DELEGATION(524288) + DONT_EXPIRE
        "svc_backup": 590336,
        "svc_sql": 66048,
        "svc_gateway": 66048,
    }
    # PITFALL 2026-11-04: aops must stay msDS=0 (KDC default negotiation).
    # Pinning the *client* account to 24 (AES) makes impacket's default RC4
    # AS-REQ yield a session-key mismatch -> every TGS fails with
    # KRB_AP_ERR_INAPP_CKSUM. svc_* accounts STAY 24: samba 4.24 KDC will
    # NOT encrypt service tickets with RC4 keys (TGS ->
    # KDC_ERR_ETYPE_NOSUPP), 24=AES128+AES256 -> hashcat 18200/19900.
    msds = {"aops": 0}
    for acct, bits in uac.items():
        dn = find(samdb, f"(sAMAccountName={acct})")[0].dn
        set_attrs(samdb, dn, {
            "userAccountControl": bits,
            "msDS-SupportedEncryptionTypes": msds.get(acct, 24),
        })

    # --- confidential flags ---------------------------------------------
    dn = find(samdb, "(sAMAccountName=svc_gateway)")[0].dn
    set_attrs(samdb, dn, {"msLite-Flag": ENV["FLAG_LOCAL"]})
    dn = find(samdb, "(sAMAccountName=DC01$)")[0].dn
    set_attrs(samdb, dn, {"msLite-Flag": ENV["FLAG_PROOF"]})

    # --- ACL chain -------------------------------------------------------
    # e.jones owns (GenericAll) the group and svc_gateway
    # NOTE: write the FULL mask, not 'GA' — the server stores GA expanded
    # (CCDCLCSWRPWPDTLOCRSDRCWDWO) but local from_sddl/as_sddl round-trip
    # keeps 'GA', so a GA literal never matches stored form for dedup (实测)
    for target in (f"CN=Tier-2-Operators,CN=Users,{base}",
                   find(samdb, "(sAMAccountName=svc_gateway)")[0].dn):
        append_dacl(samdb, str(target),
                    f"(A;;CCDCLCSWRPWPDTLOCRSDRCWDWO;;;{jones_sid})")
    # Tier-2-Operators gets DCSync (replication) rights at the domain root
    # DCSync needs BOTH Get-Changes (1131f6aa) + Get-Changes-All (1131f6ad).
    # 91cdb660 is User-Force-Change-Password — NOT a replication right (kept
    # on purpose as a bonus flaw: T2 can reset any password =1-2 path to DA).
    for guid in ("1131f6aa-9c07-11d1-f79f-00c04fc2dcd2",   # Get-Changes
                 "1131f6ad-9c07-11d1-f79f-00c04fc2dcd2",   # Get-Changes-All
                 "91cdb660-53ac-11d2-a579-0000f875e0ed"):  # Force-Change-Pw
        append_dacl(samdb, base,
                    f"(OA;CI;CR;{guid};;{t2_sid})")

    # --- decoys on SYSVOL -------------------------------------------------
    # path order matters: ',DC=' -> '.' BEFORE stripping 'DC='
    # (reverse order yields 'lite,corp')
    notes = os.path.join("/var/lib/samba/sysvol", base.replace(",DC=", ".").replace("DC=", "").lower(),
                         "scripts", "notes.txt")
    os.makedirs(os.path.dirname(notes), exist_ok=True)
    with open(notes, "w") as f:
        f.write(
            "notes - IT dept scratch pad\n"
            "- jenkins token rotation still blocked; svc_jenkins parked\n"
            f"- old token: {ENV['FLAG_DECOY']}\n"
            "- WinRM box mssql01 was decommissioned (SPN left behind)\n"
            "- remember to retire legacy 'Tier-2-Operators' group next sprint\n")
    log(f"decoy notes written: {notes}")

    open(MARKER, "w").write("done\n")
    log("seed complete")

if __name__ == "__main__":
    sys.exit(main())
