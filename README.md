# agentsh + Freestyle

Runtime security governance for AI agents using [agentsh](https://github.com/canyonroad/agentsh) v0.20.3 with [Freestyle](https://freestyle.sh) VMs.

## Why agentsh + Freestyle?

**Freestyle provides isolation. agentsh provides governance.**

Freestyle VMs give AI agents a fast, snapshot-based, disposable compute environment. But isolation alone doesn't prevent an agent from:

- **Exfiltrating data** to unauthorized endpoints
- **Accessing cloud metadata** (AWS/GCP/Azure credentials at 169.254.169.254)
- **Leaking secrets** in outputs (API keys, tokens, PII)
- **Running dangerous commands** (sudo, ssh, kill, nc)
- **Reaching internal networks** (10.x, 172.16.x, 192.168.x)
- **Deleting workspace files** permanently
- **Touching system paths** (/etc, /usr/bin, /proc/1/environ)

agentsh adds the governance layer that controls what agents can do inside the VM, providing defense-in-depth:

```
+---------------------------------------------------------+
|  Freestyle VM (Isolation)                               |
|  +---------------------------------------------------+  |
|  |  agentsh (Governance)                             |  |
|  |  +---------------------------------------------+  |  |
|  |  |  AI Agent                                   |  |  |
|  |  |  - Commands are policy-checked              |  |  |
|  |  |  - Network requests are filtered            |  |  |
|  |  |  - File I/O is intercepted (FUSE)           |  |  |
|  |  |  - System paths are restricted (Landlock)   |  |  |
|  |  |  - Secrets are stripped from environment    |  |  |
|  |  |  - All actions are audited                  |  |  |
|  |  +---------------------------------------------+  |  |
|  +---------------------------------------------------+  |
+---------------------------------------------------------+
```

## What agentsh Adds

| Freestyle Provides | agentsh Adds |
|--------------------|--------------|
| VM-level isolation | Command blocking (session API + seccomp-execve) |
| Snapshot-based fast boot | Workspace file policy (FUSE overlay) |
| API access to VM | System path enforcement (Landlock ABI v2) |
| Persistent environment | Domain allowlist/blocklist + cloud metadata blocking |
| Disposable sandboxes | Environment variable filtering (LD_PRELOAD) |
| | Secret detection and redaction |
| | Soft-delete file quarantine |
| | Memory caps and command timeouts |
| | Complete audit logging (SQLite) |

## Backend Status on Freestyle

Verified on agentsh 0.20.3+be96a4d2, Freestyle kernel 6.1.0-15-freestyle. Protection score: **65/100**.

| Layer | Backend | Status |
|---|---|---|
| Command control | seccomp-execve + session API | Enforced (install-probe confirmed) |
| Socket-family / CVE mitigation | seccomp socket rules + `dirtyfrag-conservative` set | Enforced |
| Workspace files | FUSE per-session overlay | Enforced |
| System path files | Landlock ABI v2 (per command via unixwrap) | Enforced |
| Network policy | userspace proxy + Landlock | Enforced |
| Memory + cmd timeout | systemd + agentsh server | Enforced |
| Resource limits (cgroups) | cgroups v2 top-level fallback | Partial -- process migration gap |
| eBPF cgroup/connect hooks | cilium/ebpf CO-RE | Off -- kernel ships without BTF |
| Landlock network ABI | Landlock ABI v4 | Off -- needs kernel 6.7+ |
| Capability drop | systemd CapabilityBoundingSet (10 of 41 caps) | Enforced (server process) |
| PID namespace | unshare/clone | Off -- host namespace |
| Systemd hardening | NoNewPrivileges, RestrictAddressFamilies, etc. | Enforced |

The full test suite (`npm test`) runs **64 assertions across 14 categories** and lands at **64/64 passing** on a clean run. The red team simulation (`npm run demo:attack`) blocks **41 of 44 attacks (93%)**.

### agentsh v0.20.3 Notes

This repo pins the Linux `.deb` release asset for agentsh `v0.20.3` — a patch bump over `v0.20.2` on the same `v0.20.x` line, verified with identical results (`npm test` 64/64, `npm run demo:attack` 41/44). The `v0.20.x` highlights below carry over unchanged; how they land on Freestyle:

- **Honest detect + real seccomp install-probe** (#389/#392). `agentsh detect` now confirms seccomp by attempting an actual `SECCOMP_RET_USER_NOTIF` install rather than a read-only kernel probe. On Freestyle the install **succeeds** (`seccomp_user_notify ✓`, `Seccomp_filters: 13`), so `COMMAND CONTROL 25/25` via `seccomp-execve` is genuinely enforced — not an overstatement.
- **Interception-aware opaque shell-c + `sandbox.seccomp.shellc.opaque` knob** (#381/#386). With execve interception active, an unparseable `bash -c`/`sh -c` script would, by default (`enforce`), run while every inner `execve` is policed. We pin **`opaque: deny`** so opaque scripts stay fail-closed (`shellc-opaque-script`, exit 126) — derivable simple commands and the session API are unaffected.
- **Dirty Frag mitigation set** (#293). `sandbox.seccomp.mitigation_sets: [dirtyfrag-conservative]` blocks the Openwall Dirty Frag (2026-05-07) socket tuples — `AF_RXRPC` and `AF_NETLINK`/`NETLINK_XFRM` — via seccomp socket rules. This works on Freestyle's BTF-less kernel because it needs no eBPF.
- **Socket-family blocking** (#261). Seccomp/ptrace-based default-on block list for 12 niche `AF_*` families that are recurring kernel attack entry points.

The Freestyle posture is otherwise unchanged: eBPF stays disabled because the kernel lacks BTF (`/sys/kernel/btf/vmlinux` missing), Landlock is ABI v2 (network ABI v4 needs kernel 6.7+), and cgroup PID/CPU/I/O limits remain a documented process-migration gap. The kernel line has advanced to `6.1.0-15-freestyle`.

## Quick Start

### Prerequisites

- Node.js 18+
- [Freestyle](https://freestyle.sh) account and API key
- Set environment variables in `.env`:
  ```
  FREESTYLE_API_KEY=your_api_key
  ```

### Build and Test

```bash
git clone https://github.com/canyonroad/agentsh-freestyle
cd agentsh-freestyle
npm install
cp .env.example .env
# Add your Freestyle API key to .env

# Run the blocking demo
npx tsx src/demo-blocking.ts

# Run the full test suite (64 tests)
npm test
```

## How It Works

agentsh uses the HTTP session API to evaluate every command against `command_rules` before execution. System paths are protected by a per-command Landlock ruleset applied via `agentsh-unixwrap`:

```
vm.exec("sudo whoami")
        |
        v
+---------------------------+
|  POST /api/v1/sessions/   |  Session API
|  {id}/exec                |  evaluates command_rules
+-----------+---------------+
            |
            v
+---------------------------+
|  agentsh-unixwrap         |  Applies Landlock ABI v2
|  (per-command sandbox)    |  for system path enforcement
+-----------+---------------+
            |
     +------+------+
     v             v
+----------+  +----------+
|  ALLOW   |  |  BLOCK   |
| exit: 0  |  | exit:126 |
+----------+  +----------+
```

Two execution modes are exposed:

- **`execDirect(command, args)`** -- sends the command directly to the session API. The server evaluates it against `command_rules` and returns `E_POLICY_DENIED` (exit 126) for blocked commands. **Use this for policy enforcement.**
- **`exec(command)`** -- convenience helper for simple shell-like strings. Simple commands are parsed and sent through `execDirect()` so `command_rules` still apply. Commands requiring shell metacharacters fall back to `/bin/bash.real -c`, where agentsh v0.20.x derives simple payloads for policy checks and fails closed on opaque scripts (`sandbox.seccomp.shellc.opaque: deny`) when restrictive command rules are present.

The `demo:multi-context` demo shows direct commands, derived shell payloads, and opaque shell-script denial explicitly.

## Configuration

Security policy is defined in two files:

- **`config.yaml`** -- Server configuration: HTTP/gRPC, sessions, [FUSE](https://www.agentsh.org/docs/#fuse) toggles, [seccomp](https://www.agentsh.org/docs/#seccomp) (including `shellc.opaque: deny` and the `dirtyfrag-conservative` mitigation set), top-level [Landlock](https://www.agentsh.org/docs/#landlock) defence-in-depth, audit, DLP. `sandbox.network.ebpf.enabled: false` because Freestyle's kernel lacks BTF.
- **`default.yaml`** -- [Policy rules](https://www.agentsh.org/docs/#policy-reference) (~640 lines): [command rules](https://www.agentsh.org/docs/#command-rules), [network rules](https://www.agentsh.org/docs/#network-rules), [file rules](https://www.agentsh.org/docs/#file-rules), [environment policy](https://www.agentsh.org/docs/#environment-policy), resource limits.

See the [agentsh documentation](https://www.agentsh.org/docs/) for the full policy reference.

## Project Structure

```
agentsh-freestyle/
├── config.yaml                  # Server config (FUSE, seccomp, Landlock, audit)
├── default.yaml                 # Security policy (commands, network, files, env)
├── agentsh-startup.sh           # VM startup (server + shim)
├── src/
│   ├── vm-agentsh.ts            # VmAgentsh integration with Freestyle SDK
│   ├── test-template.ts         # Full test suite (64 tests, 14 categories)
│   ├── build-snapshot.ts        # Snapshot baker
│   ├── demo-blocking.ts         # Command and filesystem blocking
│   ├── demo-network.ts          # Network policy blocking
│   ├── demo-quarantine.ts       # Soft-delete and quarantine recovery
│   ├── demo-env-filtering.ts    # Environment variable filtering
│   ├── demo-detect.ts           # Security capability detection
│   ├── demo-audit.ts            # Audit trail and event logging
│   ├── demo-attack-sim.ts       # Red team attack simulation (44 attacks)
│   ├── demo-resource-limits.ts  # Resource limits (PID, memory, CPU, I/O)
│   ├── demo-multi-context.ts    # Direct API, shell derivation, opaque shell blocking
│   ├── demo-fuse-protection.ts  # FUSE workspace + Landlock system paths
│   ├── diag-kernel.ts           # Bare vs agentsh-provisioned VM probe
│   └── diag-ebpf.ts             # Focused eBPF/BTF probe
└── package.json
```

## Testing

The `test-template.ts` script creates a Freestyle VM and runs 64 security tests across 14 categories:

- **Installation** -- agentsh binary, seccomp capability detection
- **Server & config** -- health check, policy/config files, FUSE deferred
- **Shell shim** -- bash.real preserved, unixwrap installed
- **Policy evaluation** -- static policy-test for sudo, echo, workspace, /etc
- **Security diagnostics** -- agentsh detect: seccomp, cgroups_v2, landlock; ebpf unavailable
- **Command blocking (session API)** -- sudo, su, ssh, kill, rm -rf blocked; echo, python3, git allowed
- **Network blocking** -- localhost/registries allowed; metadata, evil.com, private nets blocked
- **Environment policy** -- AWS_*/SECRET_*/TOKEN* filtered, HOME/PATH preserved
- **File I/O** -- workspace/tmp writes allowed; /etc, /usr/bin writes blocked
- **Landlock per command** -- /etc, /usr/bin, /proc/sys writes EACCES from kernel
- **Multi-context blocking** -- direct API, shell derivation, opaque shell blocking
- **FUSE workspace** -- session overlay exists, soft-delete create/rm/verify
- **Credential blocking** -- ~/.ssh/id_rsa, ~/.aws/credentials blocked
- **Resource limits** -- memory caps and command timeouts trip; PID/CPU/IO documented as gap

```bash
npm test
```

## Demos

| Command | What It Shows |
|---|---|
| `npm run demo:blocking` | Command blocking + workspace + system path access |
| `npm run demo:detect` | Kernel capability detection -- protection score and active backends |
| `npm run demo:network` | Network policy -- localhost allowed, metadata/private networks blocked |
| `npm run demo:audit` | Audit trail -- queries SQLite event log |
| `npm run demo:quarantine` | Soft-delete -- workspace deletes quarantine files |
| `npm run demo:env` | Environment filtering -- secrets stripped, safe vars passed through |
| `npm run demo:attack` | Red team simulation -- 44 attacks across recon/privesc/lateral/exfil (93% blocked) |
| `npm run demo:resources` | Resource limits -- PID bomb, memory bomb, CPU spin, I/O flood, cgroup status |
| `npm run demo:multi-context` | Command enforcement model -- direct API, shell derivation, opaque shell blocking |
| `npm run demo:fuse` | FUSE workspace + Landlock system path enforcement |
| `npm run diag:kernel` | Ground-truth kernel probe -- bare VM and agentsh-provisioned VM side by side |
| `npm run diag:ebpf` | Focused eBPF/BTF probe -- verifies the BTF-missing claim |

## For Freestyle Engineers

agentsh's protection score on Freestyle is currently **65/100**. The items below are kernel-level changes that would unlock the remaining network monitoring points.

| Change | What It Unlocks | Score Impact | Difficulty |
|---|---|---|---|
| **`CONFIG_DEBUG_INFO_BTF=y`** in kernel build | eBPF cgroup/connect hooks -- agentsh can attach BPF programs to intercept `connect()` at the kernel level, replacing the userspace proxy for network monitoring. Also enables cilium/ebpf CO-RE relocation for portable BPF programs. Add `CONFIG_DEBUG_INFO_BTF_MODULES=y` for module BTF. | +10 pts (NETWORK) | Kernel config flag |
| **Upgrade kernel to 6.7+** | Landlock ABI v4 -- kernel-level TCP bind/connect filtering. agentsh can restrict which ports and addresses a process may bind or connect to, enforced by the kernel rather than a userspace proxy. Intermediate: 6.4+ gives ABI v3 (file truncate restriction). | +10 pts (NETWORK) | Kernel upgrade |

**Quick win**: `CONFIG_DEBUG_INFO_BTF=y` is a single kernel config flag -- no code changes, unlocks eBPF.

**Medium effort**: Kernel 6.7+ unlocks Landlock network ABI v4, giving agentsh kernel-enforced TCP filtering.

## Related Projects

- [agentsh](https://github.com/canyonroad/agentsh) -- Runtime security for AI agents ([docs](https://www.agentsh.org/docs/))
- [Freestyle](https://freestyle.sh) -- Freestyle builds VM Sandbox infrastructure for AI Agents. Freestyle VMs are full hardware virtualized machines that start in ~300ms.

## License

MIT
