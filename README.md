# agentsh + Freestyle

Runtime security governance for AI agents using [agentsh](https://github.com/canyonroad/agentsh) v0.18.0 with [Freestyle](https://freestyle.sh) VMs.

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

Verified on agentsh v0.18.0, Freestyle kernel 6.1.0-7-freestyle:

| Layer | Backend | Status |
|---|---|---|
| Command control | seccomp-execve + session API | Enforced |
| Workspace files | FUSE per-session overlay | Enforced |
| System path files | Landlock ABI v2 (per command) | Enforced |
| Network policy | userspace proxy + Landlock | Enforced |
| Capability drop | capability(7) | Enforced |
| Memory + cmd timeout | systemd + agentsh server | Enforced |
| PID / CPU / disk I/O caps | cgroups v2 | Partial -- see Known Limitations |
| eBPF cgroup/connect hooks | cilium/ebpf CO-RE | Off -- kernel ships without BTF |
| Landlock network ABI | Landlock ABI v4 | Off -- needs kernel 6.7+ |

The full test suite (`npm test`) runs **64 assertions across 14 categories** and lands at **64/64 passing** on a clean run. The red team simulation (`npm run demo:attack`) blocks **41 of 44 attacks (93%)**.

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
- **`exec(command)`** -- wraps in `/bin/bash.real -c "..."` for shell features (pipes, redirections). The session API only sees `bash.real` as the top-level command, so sub-commands within bash are **not** evaluated against `command_rules` (Landlock still applies via unixwrap).

The `demo:multi-context` demo shows this distinction explicitly.

## Configuration

Security policy is defined in two files:

- **`config.yaml`** -- Server configuration: HTTP/gRPC, sessions, [FUSE](https://www.agentsh.org/docs/#fuse) toggles, [seccomp](https://www.agentsh.org/docs/#seccomp), top-level [Landlock](https://www.agentsh.org/docs/#landlock) defence-in-depth, audit, DLP. `sandbox.network.ebpf.enabled: false` because Freestyle's kernel lacks BTF.
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
│   ├── demo-multi-context.ts    # Direct API blocking vs bash sub-process
│   ├── demo-fuse-protection.ts  # FUSE workspace + Landlock system paths
│   ├── diag-kernel.ts           # Bare vs agentsh-provisioned VM probe
│   └── diag-ebpf.ts             # Focused eBPF/BTF probe
└── package.json
```

## Testing

The `test-template.ts` script creates a Freestyle VM and runs 64 security tests across 14 categories:

- **Installation** -- agentsh binary, seccomp linkage, kernel version
- **Server & config** -- health check, policy/config files, FUSE deferred
- **Shell shim** -- bash.real preserved, unixwrap installed
- **Policy evaluation** -- static policy-test for sudo, echo, workspace, /etc
- **Security diagnostics** -- agentsh detect: seccomp, cgroups_v2, landlock; ebpf unavailable
- **Command blocking (session API)** -- sudo, su, ssh, kill, rm -rf blocked; echo, python3, git allowed
- **Network blocking** -- localhost/registries allowed; metadata, evil.com, private nets blocked
- **Environment policy** -- AWS_*/SECRET_*/TOKEN* filtered, HOME/PATH preserved
- **File I/O** -- workspace/tmp writes allowed; /etc, /usr/bin writes blocked
- **Landlock per command** -- /etc, /usr/bin, /proc/sys writes EACCES from kernel
- **Multi-context blocking** -- direct API vs bash sub-process behavior
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
| `npm run demo:multi-context` | Command enforcement model -- direct API blocking vs bash sub-process |
| `npm run demo:fuse` | FUSE workspace + Landlock system path enforcement |
| `npm run diag:kernel` | Ground-truth kernel probe -- bare VM and agentsh-provisioned VM side by side |
| `npm run diag:ebpf` | Focused eBPF/BTF probe -- verifies the BTF-missing claim |

## Known Limitations

These are Freestyle-kernel-specific gaps that the integration documents transparently rather than papers over. Full technical write-ups live in [`docs/superpowers/specs/`](docs/superpowers/specs/).

- **PID / CPU / disk I/O caps don't enforce.** v0.18.0 creates `/sys/fs/cgroup/agentsh.slice` and per-command sub-cgroups, but spawned processes are never migrated into them. Memory caps and command timeouts still trip via systemd and the agentsh server. Tracked at [canyonroad/agentsh#197](https://github.com/canyonroad/agentsh/issues/197).
- **Landlock derivation is base-directory granular.** Auto-derivation collapses `file_rules` paths at the first glob character, so `/etc/passwd`, `/etc/hosts`, and `/etc/shadow` all share one `/etc` allow. Tightening this needs finer-grained derivation in agentsh.
- **`bash.real` bypasses `command_rules`.** The session API only evaluates the top-level command, so `agentsh.exec("sudo whoami")` runs as `bash.real -c "sudo whoami"` and the policy never sees `sudo`. Use `execDirect('sudo', ['whoami'])` for command-policy enforcement; Landlock still applies either way.
- **eBPF cgroup/connect hooks cannot load.** Freestyle's kernel ships without BTF (`/sys/kernel/btf/vmlinux` missing), so cilium/ebpf CO-RE programs cannot relocate. The userspace proxy and Landlock cover the network gate. Run `npm run diag:ebpf` to reproduce; tracked at [canyonroad/agentsh#217](https://github.com/canyonroad/agentsh/issues/217). Enabling `CONFIG_DEBUG_INFO_BTF=y` in the Freestyle kernel build would unblock this.

## Related Projects

- [agentsh](https://github.com/canyonroad/agentsh) -- Runtime security for AI agents ([docs](https://www.agentsh.org/docs/))
- [Freestyle](https://freestyle.sh) -- Snapshot-based VM infrastructure for AI agents

## License

MIT
