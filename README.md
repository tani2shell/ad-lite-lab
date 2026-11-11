# ad-lite-lab — a single-container Active Directory lab

**English** | [日本語](README.ja.md) | [简体中文](README.zh.md)

A compact Active Directory attack lab: one Samba 4.24 domain controller
(`dc01.lite.corp`, domain `LITE.CORP`) in a single Docker container, seeded with
users, groups, service accounts, delegations and a deliberately designed ACL
chain. Two flags, one intended path, no Windows licensing, ~1.5 GB RAM.

Built for practising the AD tradecraft that multi-VM labs make expensive:
anonymous-surface enumeration, dictionary-reachable entry credentials, ACL
reconnaissance, group-membership abuse, and reading data that ordinary binds
cannot see. The intended solve is documented in
[docs/SOLUTION.md](docs/SOLUTION.md) — open it only after you finish (or give up).

## Why this exists

Full GOAD-style ranges need 3+ Windows VMs and 12–18 GB of RAM — and are
practically unusable on Apple Silicon. `ad-lite-lab` keeps the *identity
attack surface* (enumeration → entry → ACL abuse → replication-scoped data)
in one ARM64-friendly container while keeping every step genuinely solvable
blind. It was built and calibrated by an AI-agent attack pipeline (see
[Battle-tested](#battle-tested-calibration) below), which means every wall you
can hit was hit first by a machine, and every intended clue verified reachable.

## Requirements

- Docker (Engine or OrbStack/Docker Desktop) or Podman with compose support
- 2 vCPU / 2 GB RAM free for the DC container
- An attacker box that can reach the container's published ports
  (Kali recommended; the scripts in `scripts/` assume Debian-family + sudo)
- Clock skew between attacker and DC under 5 minutes (Kerberos 101)

## Quick start

```bash
git clone https://github.com/tani2shell/ad-lite-lab.git
cd ad-lite-lab

# 1. One-shot bring-up: generates secrets.env + flags, provisions the domain,
#    starts the DC, waits for the LDAP socket, seeds accounts/groups/ACLs/flags.
./forge_samba.sh provision        # first run takes a few minutes

# 2. Confirm the DC is alive
./forge_samba.sh status
./forge_samba.sh logs 50

# 3. (Attacker box) wire host resolution + Kerberos realm to the DC
sudo bash scripts/kali_wiring.sh  # adds /etc/hosts + /etc/krb5.conf.d entries
```

The DC is published on the standard AD ports **plus** mirror ports `1088` (Kerberos)
and `1445` (SMB) — on macOS the host OS shadows 88/445, so see
[Platform matrix](#platform-matrix). Default attacker posture for this lab:

| Tool posture | Value |
|---|---|
| Domain | `LITE.CORP` (NetBIOS: `LITE`) |
| DC hostname | `dc01.lite.corp` |
| `-dc-ip` | the Docker host address your attacker box uses (see platform matrix) |
| SMB port | `445` on Linux; `--port 1445` on macOS (netexec: use `--port`, **not** `-p`) |

Operational commands:

```bash
./scripts/acceptance_battery.sh   # 7-check health battery (run from attacker box)
bash scripts/reseed.sh            # idempotent re-seed (flags stay stable)
./forge_samba.sh reset            # full wipe + re-provision + re-seed
./forge_samba.sh down             # stop; volumes persist
```

### Custom flags & credentials

`secrets.env` (generated at first provision, never committed) holds the domain
admin / service credentials and the two flag values; `secrets.env.example`
documents the shape. Edit it, then run `scripts/reseed.sh` to re-apply.
Flags land in `flags/local.flag` / `flags/proof.flag` for your scoring side;
the solver reads them from AD, not from disk.

## What's in the box (no spoilers)

- 1 domain controller, 2 published flags, 1 intended chain; several decoys
- Accounts with realistic AD quirks: SPNs, delegation flags, tiered groups,
  a custom schema attribute
- Domain policy tuned so dictionary-spray entry is possible and reproducible
- `docs/SOLUTION.md` — intended path, alternate routes, and walls that are
  *by design* vs walls that are Samba-vs-Windows reality

## Battle-tested calibration

All numbers below were produced by the authors' AI-agent attack pipeline on
this exact reference environment — **Apple M5 Ultra, local oMLX Qwen3.8-Flash-Next
model, OrbStack Kali (ARM64) attacker box**. Different models/hardware will
solve faster or slower; treat these as one calibrated data point, not a
guarantee.

- Intended solve band (informed agent): **20–40 min**
- Black-box blind solve (zero prior knowledge, fresh attacker): **2/2 flags**,
  wall clock **≈50 min** — blind dictionary spray entry → ACL escalation
  chain → flags read via the custom schema attribute (one live-fire run)
- Entry-credential reach: **19,646 requests** for a single-account blind
  spray (the entry password is a byte-exact rank-19,646 member of a common
  top-50k list; ≈130 req/s); with a 6-account round-robin width the same
  credential was first reached at ≈118k requests
- Enumeration completeness: a 2.5M-request blind run enumerated the full valid
  principal set with no misses after three independent enumeration waves

## Platform matrix

| Host | Attack posture | Notes |
|---|---|---|
| Linux (native Docker) | Direct — standard ports 88/445/389…, no tricks | Point tools at the host IP; SMB on 445 works if the host's own smbd is off or bound elsewhere |
| macOS (OrbStack / Docker Desktop) | Mirror ports: Kerberos `1088`, SMB `1445` | macOS File Sharing shadows host :88/:445 *before* Docker can bind, silently. `scripts/kali_kdc_relay.sh` + `scripts/kali_nft_persist.sh` install a systemd-persisted local `:88 → :1888 → host:1088` redirect so AD tools keep their default posture; SMB tools must use `--port 1445`. Never trust Kerberos results before `acceptance_battery.sh` check 0 passes |
| WSL2 (Docker inside WSL2) | Treat as Linux if containers publish on the WSL2 network | Windows host may also shadow 445 — if in doubt, use the 1445 mirror and the Kali scripts from a distro shell |
| Windows (native Docker Desktop) | Mirror ports as on macOS | Host smbd usually owns 445; stop it or use 1445 |
| CPU arch | arm64 and amd64 both supported | Base image is multi-arch; lab was built and calibrated on arm64 |

## Known environment quirks (learned the expensive way, so you don't pay twice)

- **netexec's `-p` is *password*, not port.** Use `--port 1445`. Passing
  `-p 1445` sends your "password" as the port and leaves SMB at 445 — on macOS
  that silently hits the host's own smbd and every credential fails with `52e`.
- **macOS UDP :88 shadow stub** answers every principal with
  `C_PRINCIPAL_UNKNOWN`. Real Samba 4.24 answers `PREAUTH_REQUIRED`. Check 0 of
  `acceptance_battery.sh` is the discriminator — run it before believing any
  Kerberos result.
- **Kali-side nft redirect rules must persist across reboots** — the scripts
  install them as a systemd unit for exactly this reason.
- Samba KDC hardening: AS-REP roasting returns no hash on 4.24 even with
  `DONT_REQ_PREAUTH` set, and impacket's Kerberoast request path hits a
  checksum interop wall (`KRB_AP_ERR_INAPP_CKSUM`). Both are *live-fire
  documented* in docs/SOLUTION.md's walls section — they are part of the lab,
  not bugs to file.

## Credits

- Base image: [`stefgo/samba-ad`](https://github.com/stefgo/samba-ad) by
  Stefano Gosso — a minimal Samba AD DC container. This lab pins it by digest
  (`sha256:d46275b4…`) and pulls it from ghcr.io; it does not redistribute the
  upstream build layers. License for the base image: upstream has not declared
  one at time of writing — we reference it as a public container image and
  attribute it by name, and have filed an upstream issue asking the author to
  add a LICENSE ([stefgo/samba-ad#1](https://github.com/stefgo/samba-ad/issues/1)).
- Everything else in this repo (compose, seed logic, ACL design, battery
  scripts, docs) is authored for this lab and offered under MIT (see LICENSE).

## Disclaimer

Lab-only. Never expose the DC to the public internet with default credentials;
it runs an intentionally vulnerable identity design.
