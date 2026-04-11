# agentsh + Freestyle Demo Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

> **Status update (2026-04-11):** This document captured the original implementation plan against agentsh **v0.16.9** and a Freestyle kernel without Landlock. The integration has since moved to **agentsh v0.18.0** on **kernel 6.1.0-7-freestyle** which now ships **Landlock**. Code snippets below are preserved as a historical record of the initial build — for the current state see `README.md` and the "v0.18.0 + Landlock Update (2026-04-11)" section in `docs/superpowers/specs/2026-04-06-agentsh-freestyle-demo-design.md`.

**Goal:** Build a comprehensive security demo showcasing agentsh runtime governance within Freestyle VMs, with a custom VmWith integration and 10 standalone demo files.

**Architecture:** Custom `VmAgentsh` integration class handles agentsh installation via VmSpec's `configureSnapshotSpec`/`configureSpec`. All command execution goes through `vm.exec()` with shell shim auto-interception. Each demo file is standalone: creates VM, runs demos, cleans up.

**Tech Stack:** TypeScript, freestyle-sandboxes SDK, tsx runtime

---

### Task 1: Project Scaffolding

**Files:**
- Create: `package.json`
- Create: `tsconfig.json`
- Create: `.env.example`
- Modify: `.gitignore` (already exists)

- [ ] **Step 1: Create package.json**

```json
{
  "name": "agentsh-freestyle",
  "private": true,
  "type": "module",
  "scripts": {
    "test": "tsx src/test-template.ts",
    "build-snapshot": "tsx src/build-snapshot.ts",
    "demo:blocking": "tsx src/demo-blocking.ts",
    "demo:audit": "tsx src/demo-audit.ts",
    "demo:network": "tsx src/demo-network.ts",
    "demo:quarantine": "tsx src/demo-quarantine.ts",
    "demo:env": "tsx src/demo-env-filtering.ts",
    "demo:detect": "tsx src/demo-detect.ts",
    "demo:attack": "tsx src/demo-attack-sim.ts",
    "demo:resources": "tsx src/demo-resource-limits.ts",
    "demo:multi-context": "tsx src/demo-multi-context.ts",
    "demo:fuse": "tsx src/demo-fuse-protection.ts"
  },
  "dependencies": {
    "freestyle-sandboxes": "latest",
    "dotenv": "^17.2.3",
    "tsx": "^4.21.0",
    "typescript": "^5.9.3"
  }
}
```

- [ ] **Step 2: Create tsconfig.json**

```json
{
  "compilerOptions": {
    "target": "ES2022",
    "module": "ESNext",
    "moduleResolution": "bundler",
    "esModuleInterop": true,
    "strict": true,
    "outDir": "dist",
    "rootDir": "src",
    "skipLibCheck": true
  },
  "include": ["src/**/*.ts"]
}
```

- [ ] **Step 3: Create .env.example**

```
FREESTYLE_API_KEY=your_freestyle_api_key_here
```

- [ ] **Step 4: Install dependencies**

Run: `npm install`
Expected: node_modules created, package-lock.json generated

- [ ] **Step 5: Commit**

```bash
git add package.json tsconfig.json .env.example .gitignore
git commit -m "feat: project scaffolding with freestyle-sandboxes"
```

---

### Task 2: Config Files

**Files:**
- Create: `config.yaml`
- Create: `default.yaml`
- Create: `agentsh-startup.sh`

- [ ] **Step 1: Create config.yaml**

Adapted from E2B reference. Key change: comments reference "Freestyle" instead of "E2B".

```yaml
# agentsh server configuration for Freestyle VM sandbox
# Extends default config with settings optimized for Freestyle environment

server:
  http:
    addr: "127.0.0.1:18080"
    read_timeout: "30s"
    write_timeout: "60s"
    max_request_size: "10MB"
  grpc:
    enabled: true
    addr: "127.0.0.1:9090"

auth:
  type: "none"

logging:
  level: "info"
  format: "text"
  output: "stderr"

sessions:
  base_dir: "/var/lib/agentsh/sessions"
  max_sessions: 100
  default_timeout: "1h"
  default_idle_timeout: "15m"
  cleanup_interval: "5m"

audit:
  enabled: true
  storage:
    sqlite_path: "/var/lib/agentsh/events.db"

sandbox:
  enabled: true
  allow_degraded: true

  limits:
    max_memory_mb: 4096
    max_cpu_percent: 100
    max_processes: 256

  fuse:
    enabled: true
    deferred: true
    deferred_marker_file: "/tmp/.agentsh-fuse-enabled"
    deferred_enable_command: ["sudo", "/bin/chmod", "666", "/dev/fuse"]
    audit:
      mode: "soft_delete"

  network:
    enabled: true
    intercept_mode: "all"
    proxy_listen_addr: "127.0.0.1:0"

  cgroups:
    enabled: true

  seccomp:
    enabled: true
    file_monitor:
      enabled: false

  unix_sockets:
    enabled: true

security:
  mode: minimal
  strict: false

capabilities:
  allow: []

proxy:
  mode: "embedded"
  port: 0
  providers:
    anthropic: "https://api.anthropic.com"
    openai: "https://api.openai.com"

dlp:
  mode: "redact"
  patterns:
    email: true
    phone: true
    credit_card: true
    ssn: true
    api_keys: true
  custom_patterns:
    - name: openai_key
      display: OPENAI_KEY
      regex: "sk-[a-zA-Z0-9]{48,}"
    - name: anthropic_key
      display: ANTHROPIC_KEY
      regex: "sk-ant-[a-zA-Z0-9-]{95,}"
    - name: aws_access_key
      display: AWS_KEY
      regex: "AKIA[0-9A-Z]{16}"
    - name: github_pat
      display: GITHUB_TOKEN
      regex: "ghp_[a-zA-Z0-9]{36}"
    - name: github_oauth
      display: GITHUB_OAUTH
      regex: "gho_[a-zA-Z0-9]{36}"
    - name: jwt_token
      display: JWT
      regex: "eyJ[a-zA-Z0-9_-]*\\.eyJ[a-zA-Z0-9_-]*\\.[a-zA-Z0-9_-]*"
    - name: private_key
      display: PRIVATE_KEY
      regex: "-----BEGIN [A-Z]+ PRIVATE KEY-----"
    - name: slack_token
      display: SLACK_TOKEN
      regex: "xox[baprs]-[0-9]{10,13}-[0-9]{10,13}-[a-zA-Z0-9]{24}"

policies:
  dir: "/etc/agentsh/policies"
  default_policy: "default"
  env_shim_path: "/usr/lib/agentsh/libenvshim.so"

approvals:
  enabled: false
  mode: "async"
  timeout: "5m"

metrics:
  enabled: true
  path: "/metrics"

health:
  path: "/health"
  readiness_path: "/ready"

development:
  disable_auth: true
  verbose_errors: false
```

- [ ] **Step 2: Create default.yaml**

Copy the E2B `default.yaml` exactly, with two changes:
1. Replace `block-e2b-internals` rule → `block-infrastructure-internals` (remove E2B-specific paths, keep general systemd blocking)
2. Replace `block-e2b-interference` command rule → `block-infrastructure-interference` (same commands but generic name)

The full file is ~640 lines. Copy it from `/home/eran/work/canyonroad/e2b-agentsh/default.yaml` and make the two renames above. Keep all other rules identical — they are agentsh-generic, not E2B-specific.

- [ ] **Step 3: Create agentsh-startup.sh**

```bash
#!/bin/bash
# Restrict /dev/fuse to prevent any FUSE mount during snapshot
sudo /bin/chmod 600 /dev/fuse 2>/dev/null || true

# Start agentsh server (deferred FUSE: mounts on first exec, not at startup)
agentsh server >> /var/log/agentsh/server.log 2>&1 &

# Wait for server to be ready (health check loop)
for i in $(seq 1 15); do
  if curl -sf http://127.0.0.1:18080/health >/dev/null 2>&1; then break; fi
  sleep 1
done

# Install shell shim (replaces /bin/bash with agentsh shim)
sudo agentsh shim install-shell --root / --shim /usr/bin/agentsh-shell-shim --bash --i-understand-this-modifies-the-host

# Warm up the shim (/dev/fuse restricted, so deferred mount is a no-op)
/bin/bash -c "echo shim warmup ok" 2>/dev/null || true

echo "agentsh ready"
```

- [ ] **Step 4: Commit**

```bash
git add config.yaml default.yaml agentsh-startup.sh
git commit -m "feat: add agentsh config, security policy, and startup script"
```

---

### Task 3: VmAgentsh Custom Integration

**Files:**
- Create: `src/vm-agentsh.ts`

This is the core file — a `VmWith` subclass encapsulating agentsh installation and lifecycle.

- [ ] **Step 1: Create src/vm-agentsh.ts**

```typescript
import { VmWith, VmWithInstance, VmSpec } from 'freestyle-sandboxes'
import { readFileSync } from 'fs'
import { resolve } from 'path'

const AGENTSH_VERSION = 'v0.16.9'
const AGENTSH_REPO = 'erans/agentsh'
const HEALTH_URL = 'http://127.0.0.1:18080/health'

export interface ExecResult {
  stdout: string
  stderr: string
  exitCode: number
  blocked: boolean
}

export interface TestExpectation {
  blocked?: boolean
  exitCode?: number
  stdoutContains?: string
  stdoutNotContains?: string
}

export class VmAgentshInstance extends VmWithInstance {
  async waitReady(retries = 30, intervalMs = 1000): Promise<void> {
    for (let i = 0; i < retries; i++) {
      try {
        const r = await this.vm.exec(`curl -sf ${HEALTH_URL}`)
        if (r.stdout.trim() === 'ok') return
      } catch {}
      await new Promise(resolve => setTimeout(resolve, intervalMs))
    }
    // Try to get server logs for diagnostics
    let logs = ''
    try {
      const r = await this.vm.exec('tail -20 /var/log/agentsh/server.log 2>/dev/null || echo "no logs"')
      logs = r.stdout
    } catch {}
    throw new Error(`agentsh server not ready after ${retries * intervalMs / 1000}s. Logs:\n${logs}`)
  }

  async exec(command: string, timeoutMs = 30000): Promise<ExecResult> {
    const r = await this.vm.exec(command)
    return {
      stdout: r.stdout || '',
      stderr: r.stderr || '',
      exitCode: r.exitCode ?? -1,
      blocked: r.exitCode === 126,
    }
  }

  async test(
    description: string,
    command: string,
    expect: TestExpectation
  ): Promise<boolean> {
    process.stdout.write(`  ${description}... `)
    try {
      const r = await this.exec(command)

      let pass = true
      if (expect.blocked !== undefined && r.blocked !== expect.blocked) pass = false
      if (expect.exitCode !== undefined && r.exitCode !== expect.exitCode) pass = false
      if (expect.stdoutContains && !r.stdout.includes(expect.stdoutContains)) pass = false
      if (expect.stdoutNotContains && r.stdout.includes(expect.stdoutNotContains)) pass = false

      if (pass) {
        console.log('✓ PASS')
      } else {
        console.log(`✗ FAIL (exit=${r.exitCode}, blocked=${r.blocked}, stdout=${r.stdout.slice(0, 80)})`)
      }
      return pass
    } catch (err) {
      const msg = err instanceof Error ? err.message : String(err)
      console.log(`✗ ERROR: ${msg}`)
      return false
    }
  }
}

export class VmAgentsh extends VmWith<VmAgentshInstance> {
  createInstance(): VmAgentshInstance {
    return new VmAgentshInstance()
  }

  async configureSnapshotSpec(spec: VmSpec): Promise<VmSpec> {
    const version = AGENTSH_VERSION.replace(/^v/, '')
    const deb = `agentsh_${version}_linux_amd64.deb`
    const url = `https://github.com/${AGENTSH_REPO}/releases/download/${AGENTSH_VERSION}/${deb}`

    return spec
      .additionalFiles({
        '/opt/install-agentsh.sh': {
          content: [
            '#!/bin/bash',
            'set -eux',
            'apt-get update && apt-get install -y --no-install-recommends ca-certificates curl jq libseccomp2 sudo fuse3 && rm -rf /var/lib/apt/lists/*',
            `curl -fsSL -L "${url}" -o /tmp/agentsh.deb`,
            'dpkg -i /tmp/agentsh.deb',
            'rm -f /tmp/agentsh.deb',
            'agentsh --version',
            'mkdir -p /etc/agentsh/policies /var/lib/agentsh/quarantine /var/lib/agentsh/sessions /var/log/agentsh',
            'chmod 755 /etc/agentsh /etc/agentsh/policies /var/lib/agentsh /var/lib/agentsh/quarantine /var/lib/agentsh/sessions /var/log/agentsh',
            // Sudo access for agentsh and FUSE device setup
            'echo "root ALL=(ALL) NOPASSWD: /usr/bin/agentsh" >> /etc/sudoers',
            'echo "root ALL=(ALL) NOPASSWD: /bin/chmod 666 /dev/fuse" >> /etc/sudoers',
            'echo "root ALL=(ALL) NOPASSWD: /bin/chmod 600 /dev/fuse" >> /etc/sudoers',
            'echo "root ALL=(ALL) NOPASSWD: /bin/mknod /dev/fuse c 10 229" >> /etc/sudoers',
            'echo "user_allow_other" >> /etc/fuse.conf',
          ].join('\n'),
        },
      })
      .systemdService({
        name: 'install-agentsh',
        mode: 'oneshot',
        exec: ['bash /opt/install-agentsh.sh'],
        wantedBy: ['multi-user.target'],
      })
  }

  async configureSpec(spec: VmSpec): Promise<VmSpec> {
    const projectRoot = resolve('.')
    const configYaml = readFileSync(resolve(projectRoot, 'config.yaml'), 'utf-8')
    const defaultYaml = readFileSync(resolve(projectRoot, 'default.yaml'), 'utf-8')
    const startupSh = readFileSync(resolve(projectRoot, 'agentsh-startup.sh'), 'utf-8')

    return spec
      .additionalFiles({
        '/etc/agentsh/config.yaml': { content: configYaml },
        '/etc/agentsh/policies/default.yaml': { content: defaultYaml },
        '/opt/agentsh-startup.sh': { content: startupSh },
      })
      .systemdService({
        name: 'agentsh',
        mode: 'service',
        exec: ['bash /opt/agentsh-startup.sh'],
        env: {
          AGENTSH_SERVER: 'http://127.0.0.1:18080',
          AGENTSH_SHIM_FORCE: '1',
        },
        after: ['install-agentsh.service'],
        wantedBy: ['multi-user.target'],
      })
  }
}
```

**Note:** The exact `VmWith`/`VmWithInstance`/`VmSpec` API shapes may need adjustment after `npm install` — the freestyle-sandboxes types will be the source of truth. The structure follows the custom integrations guide at https://docs.freestyle.sh/v2/vms/custom-integrations. If the types differ, adapt the class to match the actual SDK exports.

- [ ] **Step 2: Verify types compile**

Run: `npx tsc --noEmit src/vm-agentsh.ts`
Expected: No errors (or fix import paths based on actual SDK exports)

- [ ] **Step 3: Commit**

```bash
git add src/vm-agentsh.ts
git commit -m "feat: add VmAgentsh custom integration class"
```

---

### Task 4: Shared Test Helpers

**Files:**
- Create: `src/helpers.ts`

- [ ] **Step 1: Create src/helpers.ts**

```typescript
import 'dotenv/config'
import { freestyle, VmSpec } from 'freestyle-sandboxes'
import { VmAgentsh, VmAgentshInstance, ExecResult } from './vm-agentsh.js'

export { ExecResult }

export interface DemoVm {
  vm: any  // VM instance from freestyle SDK
  agentsh: VmAgentshInstance
}

export async function createAgentshVm(): Promise<DemoVm> {
  const agentsh = new VmAgentsh()
  const { vm } = await freestyle.vms.create({
    spec: new VmSpec({
      with: { agentsh },
    }),
  })
  const instance = (vm as any).agentsh as VmAgentshInstance
  return { vm, agentsh: instance }
}

export function printSection(title: string): void {
  console.log('\n' + '='.repeat(60))
  console.log(title)
  console.log('='.repeat(60))
}

export function printResult(description: string, passed: boolean, details?: string): void {
  const icon = passed ? '✓' : '✗'
  const suffix = details ? `  (${details})` : ''
  console.log(`  ${icon} ${description}${suffix}`)
}

export function printSummary(passed: number, failed: number): void {
  console.log('\n' + '='.repeat(60))
  console.log(`RESULTS: ${passed} passed, ${failed} failed out of ${passed + failed}`)
  console.log('='.repeat(60))
}

export function truncate(str: string, maxLen = 150): string {
  if (str.length <= maxLen) return str
  return str.slice(0, maxLen) + '...'
}
```

**Note:** The exact VM type and `(vm as any).agentsh` access pattern may differ based on the freestyle SDK's `VmWith` instance access API. The E2B-style demo uses `vm.bun.install()` — freestyle might expose integrations as `vm.agentsh` directly. Adjust after seeing the SDK types.

- [ ] **Step 2: Commit**

```bash
git add src/helpers.ts
git commit -m "feat: add shared test helpers"
```

---

### Task 5: Test Template (Comprehensive Test Suite)

**Files:**
- Create: `src/test-template.ts`

This is the largest file — ~76 tests across 12 categories. Uses `vm.exec()` with shell shim interception instead of the agentsh session API (simpler than E2B reference).

- [ ] **Step 1: Create src/test-template.ts**

```typescript
import 'dotenv/config'
import { freestyle, VmSpec } from 'freestyle-sandboxes'
import { VmAgentsh } from './vm-agentsh.js'
import { printSection, printSummary } from './helpers.js'

async function main() {
  let passed = 0
  let failed = 0

  async function test(name: string, fn: () => Promise<boolean>) {
    process.stdout.write(`  ${name}... `)
    try {
      if (await fn()) {
        console.log('✓ PASS')
        passed++
      } else {
        console.log('✗ FAIL')
        failed++
      }
    } catch (err) {
      const msg = err instanceof Error ? err.message : String(err)
      console.log(`✗ ERROR: ${msg}`)
      failed++
    }
    await new Promise(resolve => setTimeout(resolve, 200))
  }

  console.log('Creating Freestyle VM with agentsh...')
  const agentshIntegration = new VmAgentsh()
  const { vm } = await freestyle.vms.create({
    spec: new VmSpec({
      with: { agentsh: agentshIntegration },
    }),
  })
  const agentsh = (vm as any).agentsh

  try {
    console.log('Waiting for agentsh to be ready...')
    await agentsh.waitReady()
    console.log('agentsh ready!\n')

    // =================================================================
    // 1. INSTALLATION
    // =================================================================
    printSection('Installation')

    await test('agentsh installed', async () => {
      const r = await agentsh.exec('agentsh --version')
      return r.exitCode === 0 && r.stdout.includes('agentsh')
    })

    await test('seccomp support (libseccomp linked)', async () => {
      const r = await agentsh.exec('ldd /usr/bin/agentsh 2>&1 | grep -E "seccomp|not.*dynamic"')
      return r.stdout.includes('libseccomp')
    })

    // =================================================================
    // 2. SERVER & CONFIGURATION
    // =================================================================
    printSection('Server & Configuration')

    await test('server healthy', async () => {
      const r = await agentsh.exec('curl -s http://127.0.0.1:18080/health')
      return r.stdout.trim() === 'ok'
    })

    await test('server process running', async () => {
      const r = await agentsh.exec('ps aux | grep "agentsh server" | grep -v grep')
      return r.exitCode === 0 && r.stdout.includes('agentsh')
    })

    await test('policy file exists', async () => {
      const r = await agentsh.exec('head -5 /etc/agentsh/policies/default.yaml')
      return r.exitCode === 0 && r.stdout.includes('version')
    })

    await test('config file exists', async () => {
      const r = await agentsh.exec('head -5 /etc/agentsh/config.yaml')
      return r.exitCode === 0 && r.stdout.includes('server')
    })

    await test('FUSE deferred enabled in config', async () => {
      const r = await agentsh.exec('grep -A3 "fuse:" /etc/agentsh/config.yaml')
      return r.stdout.includes('enabled: true') && r.stdout.includes('deferred: true')
    })

    await test('seccomp enabled in config', async () => {
      const r = await agentsh.exec('grep -A1 "seccomp:" /etc/agentsh/config.yaml')
      return r.stdout.includes('enabled: true')
    })

    // =================================================================
    // 3. SHELL SHIM
    // =================================================================
    printSection('Shell Shim')

    await test('shim installed (/bin/bash is statically linked)', async () => {
      const r = await agentsh.exec('file /bin/bash')
      return r.stdout.includes('statically linked')
    })

    await test('real bash preserved (/bin/bash.real)', async () => {
      const r = await agentsh.exec('file /bin/bash.real')
      return r.exitCode === 0 && r.stdout.includes('ELF')
    })

    await test('echo through shim', async () => {
      const r = await agentsh.exec('/bin/bash -c "echo hello-shim"')
      return r.exitCode === 0 && r.stdout.includes('hello-shim')
    })

    await test('Python through shim', async () => {
      const r = await agentsh.exec("python3 -c \"print('python-ok')\"")
      return r.exitCode === 0 && r.stdout.includes('python-ok')
    })

    // =================================================================
    // 4. POLICY EVALUATION (static)
    // =================================================================
    printSection('Policy Evaluation (static)')

    await test('policy-test: sudo denied', async () => {
      const r = await agentsh.exec('agentsh debug policy-test --op exec --path sudo --json 2>&1')
      return r.stdout.includes('"deny"') && r.stdout.includes('block-shell-escape')
    })

    await test('policy-test: echo allowed', async () => {
      const r = await agentsh.exec('agentsh debug policy-test --op exec --path echo --json 2>&1')
      return r.stdout.includes('"allow"') && r.stdout.includes('allow-safe-commands')
    })

    await test('policy-test: workspace write allowed', async () => {
      const r = await agentsh.exec('agentsh debug policy-test --op write --path /home/user/test.txt --json 2>&1')
      return r.stdout.includes('"allow"')
    })

    await test('policy-test: workspace read allowed', async () => {
      const r = await agentsh.exec('agentsh debug policy-test --op read --path /home/user/test.txt --json 2>&1')
      return r.stdout.includes('"allow"')
    })

    await test('policy-test: tmp write allowed', async () => {
      const r = await agentsh.exec('agentsh debug policy-test --op write --path /tmp/test.txt --json 2>&1')
      return r.stdout.includes('"allow"') && r.stdout.includes('allow-tmp')
    })

    await test('policy-test: workspace delete is soft-delete', async () => {
      const r = await agentsh.exec('agentsh debug policy-test --op delete --path /home/user/test.txt --json 2>&1')
      return r.stdout.includes('soft-delete-workspace')
    })

    await test('policy-test: SSH key access requires approval', async () => {
      const r = await agentsh.exec('agentsh debug policy-test --op read --path /root/.ssh/id_rsa --json 2>&1')
      return r.stdout.includes('approve-ssh-access')
    })

    await test('policy-test: AWS credentials require approval', async () => {
      const r = await agentsh.exec('agentsh debug policy-test --op read --path /root/.aws/credentials --json 2>&1')
      return r.stdout.includes('approve-aws-credentials')
    })

    await test('policy-test: system path write denied', async () => {
      const r = await agentsh.exec('agentsh debug policy-test --op write --path /usr/bin/evil --json 2>&1')
      return r.stdout.includes('"deny"')
    })

    await test('policy-test: /etc write denied', async () => {
      const r = await agentsh.exec('agentsh debug policy-test --op write --path /etc/test.txt --json 2>&1')
      return r.stdout.includes('"deny"')
    })

    // =================================================================
    // 5. SECURITY DIAGNOSTICS
    // =================================================================
    printSection('Security Diagnostics')

    const detectOut = (await agentsh.exec('agentsh detect 2>&1')).stdout
    const capSection = detectOut.substring(detectOut.indexOf('CAPABILITIES'))
    function capAvailable(key: string): boolean {
      const re = new RegExp(`^\\s+${key}\\s+✓`, 'm')
      return re.test(capSection)
    }

    await test('agentsh detect: seccomp available', async () => capAvailable('seccomp_basic') || capAvailable('seccomp'))
    await test('agentsh detect: seccomp_basic available', async () => capAvailable('seccomp_basic'))
    await test('agentsh detect: cgroups_v2 available', async () => capAvailable('cgroups_v2'))
    await test('agentsh detect: landlock available', async () => capAvailable('landlock'))

    // =================================================================
    // 6. COMMAND BLOCKING
    // =================================================================
    printSection('Command Blocking')

    await test('sudo blocked', async () => {
      const r = await agentsh.exec('sudo whoami')
      return r.blocked
    })

    await test('su blocked', async () => {
      const r = await agentsh.exec('su - 2>&1')
      return r.blocked || r.exitCode !== 0
    })

    await test('ssh blocked', async () => {
      const r = await agentsh.exec('ssh localhost 2>&1')
      return r.blocked || r.exitCode !== 0
    })

    await test('kill blocked', async () => {
      const r = await agentsh.exec('kill -9 1 2>&1')
      return r.blocked || r.exitCode !== 0
    })

    await test('rm -rf blocked', async () => {
      await agentsh.exec('mkdir -p /tmp/testdir && touch /tmp/testdir/f.txt')
      const r = await agentsh.exec('rm -rf /tmp/testdir 2>&1')
      return r.blocked || r.exitCode !== 0
    })

    await test('echo allowed', async () => {
      const r = await agentsh.exec('echo policy-test')
      return r.exitCode === 0 && r.stdout.includes('policy-test')
    })

    // =================================================================
    // 7. NETWORK BLOCKING
    // =================================================================
    printSection('Network Blocking')

    await test('package registry allowed (npmjs.org)', async () => {
      const r = await agentsh.exec('curl -s --connect-timeout 10 --max-time 15 -o /dev/null -w "%{http_code}" https://registry.npmjs.org/')
      return r.stdout.trim() === '200'
    })

    await test('metadata endpoint blocked (169.254.169.254)', async () => {
      const r = await agentsh.exec('curl -s --connect-timeout 3 -o /dev/null -w "%{http_code}" http://169.254.169.254/')
      return r.stdout.includes('403') || r.exitCode !== 0
    })

    await test('evil.com blocked', async () => {
      const r = await agentsh.exec('curl -s --connect-timeout 5 -o /dev/null -w "%{http_code}" https://evil.com/')
      return r.stdout.includes('400') || r.stdout.includes('403') || r.exitCode !== 0
    })

    await test('private network blocked (10.0.0.1)', async () => {
      const r = await agentsh.exec('curl -s --connect-timeout 3 -o /dev/null -w "%{http_code}" http://10.0.0.1/')
      return r.stdout.includes('403') || r.exitCode !== 0
    })

    await test('unknown domain blocked (default-deny)', async () => {
      const r = await agentsh.exec('curl -s --connect-timeout 5 -o /dev/null -w "%{http_code}" https://api.github.com/ 2>&1')
      return r.stdout.includes('403') || r.stdout.includes('000') || r.exitCode !== 0
    })

    // =================================================================
    // 8. ENVIRONMENT POLICY
    // =================================================================
    printSection('Environment Policy')

    await test('safe vars present (HOME, PATH)', async () => {
      const r = await agentsh.exec('echo "HOME=$HOME" && echo "PATH=$PATH"')
      return r.stdout.includes('HOME=/') && r.stdout.includes('PATH=/')
    })

    await test('BASH_ENV set', async () => {
      const r = await agentsh.exec('echo $BASH_ENV')
      return r.stdout.includes('bash_startup') || r.exitCode === 0
    })

    // =================================================================
    // 9. FILE I/O
    // =================================================================
    printSection('File I/O Enforcement')

    await test('write to workspace succeeds', async () => {
      const r = await agentsh.exec('echo "fileio-test" > /home/user/fileio-test.txt && cat /home/user/fileio-test.txt')
      return r.exitCode === 0 && r.stdout.includes('fileio-test')
    })

    await test('write to /tmp succeeds', async () => {
      const r = await agentsh.exec('echo "tmp-test" > /tmp/fileio-test.txt && cat /tmp/fileio-test.txt')
      return r.exitCode === 0 && r.stdout.includes('tmp-test')
    })

    await test('write to /etc blocked', async () => {
      const r = await agentsh.exec('echo "hack" > /etc/test_file 2>&1')
      return r.exitCode !== 0
    })

    await test('Python write to /etc blocked', async () => {
      const r = await agentsh.exec("python3 -c \"open('/etc/fuse_test','w').write('hack')\" 2>&1")
      return r.exitCode !== 0
    })

    await test('symlink escape to /etc/shadow blocked', async () => {
      const r = await agentsh.exec('ln -sf /etc/shadow /tmp/shadow_link && cat /tmp/shadow_link 2>&1')
      return r.exitCode !== 0
    })

    await test('read /proc/1/environ blocked', async () => {
      const r = await agentsh.exec('cat /proc/1/environ 2>&1')
      return r.exitCode !== 0
    })

    // =================================================================
    // 10. MULTI-CONTEXT BLOCKING
    // =================================================================
    printSection('Multi-Context Command Blocking')

    await test('env sudo blocked', async () => {
      const r = await agentsh.exec('env sudo whoami 2>&1')
      return r.exitCode !== 0
    })

    await test('xargs sudo blocked', async () => {
      const r = await agentsh.exec('echo whoami | xargs sudo 2>&1')
      return r.exitCode !== 0
    })

    await test('find -exec sudo blocked', async () => {
      const r = await agentsh.exec('find /tmp -maxdepth 0 -exec sudo whoami \\; 2>&1')
      return r.exitCode !== 0 || !r.stdout.match(/^root$/m)
    })

    await test('nested script sudo blocked', async () => {
      await agentsh.exec('printf "#!/bin/sh\\nsudo whoami\\n" > /tmp/escalate.sh && chmod +x /tmp/escalate.sh')
      const r = await agentsh.exec('/tmp/escalate.sh 2>&1')
      return r.exitCode !== 0
    })

    await test('Python subprocess sudo blocked', async () => {
      const r = await agentsh.exec("python3 -c \"import subprocess; r=subprocess.run(['sudo','whoami'], capture_output=True, text=True); print(r.stdout or r.stderr); exit(r.returncode)\" 2>&1")
      return r.exitCode !== 0
    })

    await test('env whoami allowed', async () => {
      const r = await agentsh.exec('env whoami')
      return r.exitCode === 0
    })

    await test('find -exec echo allowed', async () => {
      const r = await agentsh.exec('find /tmp -maxdepth 0 -exec echo found \\;')
      return r.exitCode === 0 && r.stdout.includes('found')
    })

    // =================================================================
    // 11. FUSE WORKSPACE & SOFT DELETE
    // =================================================================
    printSection('FUSE Workspace & Soft Delete')

    await test('create file for soft-delete', async () => {
      const r = await agentsh.exec("python3 -c \"open('/home/user/soft_del_test.txt','w').write('important data\\n')\"")
      return r.exitCode === 0
    })

    await test('rm file (soft-deleted)', async () => {
      const r = await agentsh.exec('rm /home/user/soft_del_test.txt 2>&1')
      return r.exitCode === 0
    })

    await test('file gone from original location', async () => {
      const r = await agentsh.exec('test -f /home/user/soft_del_test.txt && echo exists || echo gone')
      return r.stdout.includes('gone')
    })

    await test('agentsh trash list shows file', async () => {
      const r = await agentsh.exec('agentsh trash list 2>&1')
      return r.stdout.includes('soft_del_test') || r.exitCode === 0
    })

    // =================================================================
    // 12. CREDENTIAL BLOCKING
    // =================================================================
    printSection('Credential Blocking')

    await test('read ~/.ssh/id_rsa blocked', async () => {
      const r = await agentsh.exec('cat /home/user/.ssh/id_rsa 2>&1')
      return r.exitCode !== 0
    })

    await test('read ~/.aws/credentials blocked', async () => {
      const r = await agentsh.exec('cat /home/user/.aws/credentials 2>&1')
      return r.exitCode !== 0
    })

    await test('read /proc/1/environ blocked', async () => {
      const r = await agentsh.exec('cat /proc/1/environ 2>&1')
      return r.exitCode !== 0
    })

    // =================================================================
    // RESULTS
    // =================================================================
    printSummary(passed, failed)

  } catch (error) {
    console.error('Fatal:', error)
    failed++
  } finally {
    console.log('\nCleaning up VM...')
    // Freestyle VM cleanup - check SDK for exact method
    // vm.stop() or vm.destroy() or freestyle.vms.delete(vmId)
    console.log('Done.')
  }

  process.exit(failed > 0 ? 1 : 0)
}

main().catch(console.error)
```

- [ ] **Step 2: Commit**

```bash
git add src/test-template.ts
git commit -m "feat: add comprehensive test suite (76 tests, 12 categories)"
```

---

### Task 6: Build Snapshot Script

**Files:**
- Create: `src/build-snapshot.ts`

- [ ] **Step 1: Create src/build-snapshot.ts**

```typescript
import 'dotenv/config'
import { freestyle, VmSpec } from 'freestyle-sandboxes'
import { VmAgentsh } from './vm-agentsh.js'

async function main() {
  console.log('Creating Freestyle VM with agentsh for snapshot...')

  const agentshIntegration = new VmAgentsh()
  const { vm } = await freestyle.vms.create({
    spec: new VmSpec({
      with: { agentsh: agentshIntegration },
    }),
  })

  const agentsh = (vm as any).agentsh

  try {
    console.log('Waiting for agentsh to be ready...')
    await agentsh.waitReady()
    console.log('agentsh ready!')

    // Verify installation
    const version = await agentsh.exec('agentsh --version')
    console.log(`agentsh version: ${version.stdout.trim()}`)

    const health = await agentsh.exec('curl -s http://127.0.0.1:18080/health')
    console.log(`Server health: ${health.stdout.trim()}`)

    const shim = await agentsh.exec('file /bin/bash')
    console.log(`Shell shim: ${shim.stdout.trim()}`)

    // Create snapshot
    console.log('\nCreating snapshot...')
    const { snapshotId } = await vm.snapshot()
    console.log(`\nSnapshot created successfully!`)
    console.log(`Snapshot ID: ${snapshotId}`)
    console.log(`\nTo use this snapshot, create VMs with:`)
    console.log(`  freestyle.vms.create({ snapshotId: '${snapshotId}' })`)

  } catch (error) {
    console.error('Error:', error)
    process.exit(1)
  }
}

main().catch(console.error)
```

- [ ] **Step 2: Commit**

```bash
git add src/build-snapshot.ts
git commit -m "feat: add build-snapshot script for image baking"
```

---

### Task 7: demo-blocking.ts

**Files:**
- Create: `src/demo-blocking.ts`

- [ ] **Step 1: Create src/demo-blocking.ts**

Port the E2B `demo-blocking.ts` to use `vm.exec()` with shell shim. Replace `Sandbox.create('e2b-agentsh')` with freestyle VM creation. Replace `sbx.commands.run()` calls with `agentsh.exec()`. Remove session API (curl-based execution). Keep the same test structure: 11 sections covering allowed commands, diagnostics, privilege escalation, network tools, system commands, recursive delete, single file delete, workspace access, blocked paths, credential access, soft-delete.

The demo should follow this pattern:
```typescript
import 'dotenv/config'
import { freestyle, VmSpec } from 'freestyle-sandboxes'
import { VmAgentsh } from './vm-agentsh.js'
import { printSection } from './helpers.js'

async function main() {
  console.log('Creating Freestyle VM with agentsh...')
  const { vm } = await freestyle.vms.create({
    spec: new VmSpec({ with: { agentsh: new VmAgentsh() } }),
  })
  const agentsh = (vm as any).agentsh

  try {
    await agentsh.waitReady()

    // Each section uses agentsh.exec(command) and checks exitCode/blocked
    // Print formatted results showing BLOCKED/ALLOWED for each command
    // ... (port all 11 sections from E2B demo-blocking.ts)

  } catch (error) {
    console.error('Error:', error)
  } finally {
    console.log('\nCleaning up...')
    console.log('Done.')
  }
}

main().catch(console.error)
```

Port all 11 sections from the E2B reference, replacing `runAgentsh(desc, command, args)` (which used curl to session API) with:
```typescript
async function run(description: string, command: string): Promise<boolean> {
  console.log(`\n--- ${description} ---`)
  const r = await agentsh.exec(command)
  if (r.blocked) {
    console.log(`✗ BLOCKED (exit: 126)`)
    return false
  } else if (r.exitCode === 0) {
    console.log(`✓ ALLOWED (exit: 0)`)
    return true
  } else {
    console.log(`✗ DENIED (exit: ${r.exitCode})`)
    return false
  }
}
```

Commands to port (adapt from E2B — use shell commands instead of `[command, args]` since we're using vm.exec with shell):
- Section 1 (Allowed): `echo Hello`, `pwd`, `id`, `ls /home`, `date`, `python3 -c "print(1)"`, `git --version`, `agentsh --version`
- Section 2 (Diagnostics): `echo $HTTPS_PROXY`, `mount | grep agentsh`, `echo $BASH_ENV`, `type kill`, `ls -la /usr/bin/ls`
- Section 3 (Privilege Escalation): `sudo whoami`, `su -`, `chroot /`
- Section 4 (Network Tools): `ssh localhost`, `nc -h`, `netcat -h`
- Section 5 (System Commands): `kill -9 1`, `shutdown now`, `systemctl status`
- Section 6 (Recursive Delete): `rm -rf /tmp/test`, `rm -r /tmp/test`, `rm --recursive /tmp/test`
- Section 7 (Single File Delete): `rm /tmp/test/file.txt`
- Section 8 (Workspace Access): Python write, cat, ls
- Section 9 (Blocked Paths): `cat /proc/1/environ`, `cat /sys/kernel/hostname`, Python write to /etc, /var
- Section 10 (Credential Access): `cat ~/.ssh/id_rsa`, `cat ~/.aws/credentials`, `cat ~/.env`
- Section 11 (Soft-Delete): Create file, delete, verify gone

- [ ] **Step 2: Commit**

```bash
git add src/demo-blocking.ts
git commit -m "feat: add command/filesystem blocking demo"
```

---

### Task 8: demo-network.ts

**Files:**
- Create: `src/demo-network.ts`

- [ ] **Step 1: Create src/demo-network.ts**

Same pattern as Task 7. Port 6 sections from E2B:
1. Localhost (allowed) — `curl http://127.0.0.1:18080/health`
2. Cloud Metadata (blocked) — `curl http://169.254.169.254/`
3. Private Networks (blocked) — `curl http://10.0.0.1/`, `curl http://192.168.1.1/`
4. Package Registries (allowed) — `curl https://registry.npmjs.org/`, `curl https://pypi.org/`
5. Unknown Domains (denied) — `curl https://example.com/`, `curl https://httpbin.org/get`
6. wget tests — `wget localhost:18080/health`, `wget http://169.254.169.254/`

- [ ] **Step 2: Commit**

```bash
git add src/demo-network.ts
git commit -m "feat: add network policy blocking demo"
```

---

### Task 9: demo-audit.ts

**Files:**
- Create: `src/demo-audit.ts`

- [ ] **Step 1: Create src/demo-audit.ts**

Port from E2B. Three phases:
1. Generate audit events (mix of allowed/blocked commands via vm.exec)
2. Query audit log (SQLite via `sqlite3 -json /var/lib/agentsh/events.db`, CLI via `agentsh events`)
3. Display formatted audit trail

- [ ] **Step 2: Commit**

```bash
git add src/demo-audit.ts
git commit -m "feat: add audit trail logging demo"
```

---

### Task 10: demo-quarantine.ts

**Files:**
- Create: `src/demo-quarantine.ts`

- [ ] **Step 1: Create src/demo-quarantine.ts**

Port from E2B. Key difference: no `sbx.files.write` for creating test files — use `vm.exec("python3 -c \"open(path,'w').write(content)\"")` instead. Five phases:
1. Create files in workspace
2. Delete files (triggers soft_delete)
3. List quarantined files via `agentsh trash list`
4. Restore a file via `agentsh trash restore <token>`
5. Verify restored file content

- [ ] **Step 2: Commit**

```bash
git add src/demo-quarantine.ts
git commit -m "feat: add soft-delete and quarantine recovery demo"
```

---

### Task 11: demo-env-filtering.ts

**Files:**
- Create: `src/demo-env-filtering.ts`

- [ ] **Step 1: Create src/demo-env-filtering.ts**

Port from E2B. Since we're using vm.exec() (not the session API), we can't inject env vars per-command. Instead, test:
1. Default allowed vars (HOME, PATH, USER) — `printenv HOME`, `printenv PATH`
2. Check that sensitive patterns are not leaked — `env | grep AWS_`, `env | grep OPENAI_`
3. Env enumeration protection — `env` command output, `printenv` output

- [ ] **Step 2: Commit**

```bash
git add src/demo-env-filtering.ts
git commit -m "feat: add environment variable filtering demo"
```

---

### Task 12: demo-detect.ts

**Files:**
- Create: `src/demo-detect.ts`

- [ ] **Step 1: Create src/demo-detect.ts**

Port from E2B. Run `agentsh detect 2>&1` and parse output for capabilities:
seccomp, seccomp_user_notify, ebpf, fuse, landlock, cgroups_v2, etc. Display formatted capability matrix.

- [ ] **Step 2: Commit**

```bash
git add src/demo-detect.ts
git commit -m "feat: add security capability detection demo"
```

---

### Task 13: demo-attack-sim.ts

**Files:**
- Create: `src/demo-attack-sim.ts`

- [ ] **Step 1: Create src/demo-attack-sim.ts**

Port from E2B. 7 phases with scorecard tracking:
1. Reconnaissance (7 attacks): cat /etc/passwd, /etc/shadow, env, /proc/1/environ, /proc/1/cmdline, nmap, ip addr
2. Credential Theft (7): ~/.ssh/id_rsa, ~/.ssh/id_ed25519, ~/.aws/credentials, ~/.aws/config, .env, .git-credentials, ~/.kube/config
3. Privilege Escalation (6): sudo su, sudo bash, su - root, chroot /, nsenter, unshare
4. Lateral Movement (6): ssh, nc, curl to 10.x, 192.168.x, 169.254.169.254, internal services
5. Data Exfiltration (5): POST to evil.com, unknown domain, wget, DNS exfil, rsync
6. Persistence (5): crontab, profile.d, trojan /usr/bin/git, systemd service, .bashrc
7. Destruction (8): rm -rf /, rm -rf /home, rm -r /tmp, shutdown, reboot, kill PID 1, killall, dd wipe

Print scorecard at end.

- [ ] **Step 2: Commit**

```bash
git add src/demo-attack-sim.ts
git commit -m "feat: add red team attack simulation demo (44 attacks)"
```

---

### Task 14: demo-resource-limits.ts

**Files:**
- Create: `src/demo-resource-limits.ts`

- [ ] **Step 1: Create src/demo-resource-limits.ts**

Port from E2B. 5 tests:
1. PID Limit (pids_max: 100) — Python fork bomb
2. Memory Limit (2048 MB) — Python memory hog allocating 3GB
3. Command Timeout — sleep 600 with short timeout
4. CPU Quota (50%) — Python CPU burn
5. Disk I/O Limits — Python write speed test

- [ ] **Step 2: Commit**

```bash
git add src/demo-resource-limits.ts
git commit -m "feat: add resource limits demo"
```

---

### Task 15: demo-multi-context.ts

**Files:**
- Create: `src/demo-multi-context.ts`

- [ ] **Step 1: Create src/demo-multi-context.ts**

Port from E2B. 7 sections:
1. Direct blocked commands (baseline)
2. Via env — `env sudo whoami`
3. Via xargs — `echo whoami | xargs sudo`
4. Via find -exec — `find /tmp -exec sudo whoami`
5. Via nested script
6. Via Python subprocess/os.system
7. Allowed safe commands via same contexts

- [ ] **Step 2: Commit**

```bash
git add src/demo-multi-context.ts
git commit -m "feat: add multi-context command blocking demo"
```

---

### Task 16: demo-fuse-protection.ts

**Files:**
- Create: `src/demo-fuse-protection.ts`

- [ ] **Step 1: Create src/demo-fuse-protection.ts**

Port from E2B. 4 sections:
1. CLI tools to protected dirs — cp to /etc, touch /etc/newfile, tee to /usr/bin, mkdir in /etc
2. Symlink escape — ln -sf /etc/shadow, ln -sf /etc/passwd + write
3. Python file I/O — read /etc/shadow, write to /etc, /usr/bin, list /root, write to /var
4. Allowed — cp within workspace, touch in /tmp, Python write to workspace/tmp

- [ ] **Step 2: Commit**

```bash
git add src/demo-fuse-protection.ts
git commit -m "feat: add FUSE/VFS file protection demo"
```

---

### Task 17: README

**Files:**
- Create: `README.md`

- [ ] **Step 1: Create README.md**

Include:
- Overview: what agentsh + Freestyle provides
- Prerequisites: Node.js 18+, Freestyle API key
- Quick Start: `npm install`, set `.env`, `npx tsx src/demo-blocking.ts`
- Available Scripts: table of all demo commands
- Image Baking: how to use `build-snapshot.ts`
- Architecture: VmAgentsh integration, security stack (5 layers), config files
- Security Policy Overview: file rules, network rules, command rules, env policy, resource limits
- Related projects: links to E2B and Daytona demos

- [ ] **Step 2: Commit**

```bash
git add README.md
git commit -m "docs: add README with quickstart and architecture overview"
```

---

### Task 18: SDK Integration Verification

After all files are written, verify the freestyle-sandboxes SDK types match our usage.

- [ ] **Step 1: Check SDK exports**

Run: `npx tsc --noEmit`

If there are type errors, the most likely issues are:
- `VmWith`/`VmWithInstance`/`VmSpec` import paths differ from what we assumed
- `vm.exec()` return type differs (might be `{ stdout, stderr, exitCode }` vs `{ result, stdout, stderr }`)
- VM creation API shape differs from `freestyle.vms.create({ spec })`
- Integration access pattern differs (might not be `vm.agentsh` — check SDK docs)

Fix any type errors by adjusting imports and types in `vm-agentsh.ts` and `helpers.ts`.

- [ ] **Step 2: Commit fixes if needed**

```bash
git add -A
git commit -m "fix: align SDK types with freestyle-sandboxes exports"
```
