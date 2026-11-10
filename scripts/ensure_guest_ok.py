#!/usr/bin/env python3
"""Ensure [sysvol]/[netlogon] have 'guest ok = yes' in live smb.conf (run inside container).
PITFALL 2026-11-04: provisioned SYSVOL has no 'guest ok' -> anonymous tree connect
NT_STATUS_ACCESS_DENIED. Directory DACLs already allow others:r, so share flag is
the only gate.
PITFALL 2026-11-08: the old 200-char tail-window check false-negatived [sysvol] when
the already-patched [netlogon] section fell inside the window -> sysvol silently
skipped after a force-recreate. Now checks per-section.
smb.conf lives in the samba-dc-etc volume -> edit persists across container restarts;
this script makes it reproducible."""
import subprocess

p = "/etc/samba/smb.conf"
lines = open(p).read().splitlines(keepends=True)
targets = {"sysvol", "netlogon"}
cur = None
has_flag = {}
for ln in lines:
    st = ln.strip()
    if st.startswith("[") and st.endswith("]"):
        cur = st[1:-1]
        has_flag.setdefault(cur, False)
    if cur in targets and st.startswith("guest ok"):
        has_flag[cur] = True

inserts = []
for sec in sorted(targets):
    if sec in has_flag and not has_flag[sec]:
        for i, ln in enumerate(lines):
            if ln.strip() == "[%s]" % sec:
                inserts.append(i + 1)
                break

if inserts:
    for i in sorted(inserts, reverse=True):
        lines.insert(i, "\tguest ok = yes\n")
    open(p, "w").write("".join(lines))
    subprocess.run(["pkill", "-x", "samba"])  # supervisord respawns with new config
    print("guest-ok applied to %d section(s), samba restarting" % len(inserts))
else:
    print("guest-ok already set")
