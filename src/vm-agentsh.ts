import { VmWith, VmWithInstance, VmSpec } from 'freestyle-sandboxes'
import { readFileSync } from 'fs'
import { resolve } from 'path'

const AGENTSH_VERSION = 'v0.18.0'
const AGENTSH_REPO = 'canyonroad/agentsh'
const AGENTSH_API = 'http://127.0.0.1:18080'
const HEALTH_URL = `${AGENTSH_API}/health`

export interface ExecResult {
  stdout: string
  stderr: string
  exitCode: number
  blocked: boolean
  rule?: string
}

export interface TestExpectation {
  blocked?: boolean
  exitCode?: number
  stdoutContains?: string
  stdoutNotContains?: string
}

export class VmAgentshInstance extends VmWithInstance {
  private sessionId: string | null = null
  private reqCounter = 0

  async waitReady(retries = 30, intervalMs = 1000): Promise<void> {
    for (let i = 0; i < retries; i++) {
      try {
        const r = await this.vm.exec({ command: `curl -sf ${HEALTH_URL}`, timeoutMs: 5000 })
        if ((r.stdout ?? '').trim() !== 'ok') throw new Error('server not ready')
        // Verify shell shim is installed (bash.real must exist)
        const s = await this.vm.exec({ command: 'stat /bin/bash.real >/dev/null 2>&1 && echo ok', timeoutMs: 5000 })
        if ((s.stdout ?? '').trim() === 'ok') return
      } catch {
        // ignore — server not ready yet
      }
      await new Promise(res => setTimeout(res, intervalMs))
    }
    let logs = ''
    try {
      const r = await this.vm.exec({ command: 'tail -20 /var/log/agentsh/server.log 2>/dev/null || echo "no logs"', timeoutMs: 5000 })
      logs = r.stdout ?? ''
    } catch {}
    throw new Error(`agentsh server not ready after ${retries * intervalMs / 1000}s. Logs:\n${logs}`)
  }

  private async ensureSession(): Promise<string> {
    if (this.sessionId) return this.sessionId
    const r = await this.vm.exec({
      command: `curl -s -X POST ${AGENTSH_API}/api/v1/sessions -H "Content-Type: application/json" -d '{"workspace":"/home/user"}'`,
      timeoutMs: 10000
    })
    const data = JSON.parse(r.stdout ?? '')
    if (data.error) throw new Error(`Session creation failed: ${data.error}`)
    this.sessionId = data.id
    return data.id
  }

  /** Shell command execution — wraps in bash.real for full shell support.
   *  Sub-commands within bash are NOT subject to command_rules. */
  async exec(command: string, timeoutMs = 30000): Promise<ExecResult> {
    return this.sessionExec({ command: '/bin/bash.real', args: ['-c', command] }, timeoutMs)
  }

  /** Direct command execution — command_rules are fully evaluated.
   *  Use for testing command policy enforcement. */
  async execDirect(command: string, args: string[] = [], timeoutMs = 30000): Promise<ExecResult> {
    return this.sessionExec({ command, args }, timeoutMs)
  }

  private async sessionExec(req: { command: string, args: string[] }, timeoutMs: number): Promise<ExecResult> {
    // Single retry on transient empty/invalid responses (curl over the
    // local socket occasionally returns empty stdout under load — see
    // intermittent npm-test failures of policy-test / shim warmup).
    let lastErr: ExecResult | null = null
    for (let attempt = 0; attempt < 2; attempt++) {
      const result = await this.sessionExecOnce(req, timeoutMs)
      const transient = result.exitCode === -1 && (result.stderr ?? '').startsWith('Invalid response')
      if (!transient) return result
      lastErr = result
      // brief backoff before retrying
      await new Promise(r => setTimeout(r, 200))
    }
    return lastErr!
  }

  private async sessionExecOnce(req: { command: string, args: string[] }, timeoutMs: number): Promise<ExecResult> {
    const sessionId = await this.ensureSession()
    const body = JSON.stringify(req)
    const reqFile = `/tmp/exec-req-${++this.reqCounter}.json`
    await this.vm.exec({ command: `cat > ${reqFile} << 'JSONEOF'\n${body}\nJSONEOF`, timeoutMs: 5000 })

    const r = await this.vm.exec({
      command: `curl -s -X POST "${AGENTSH_API}/api/v1/sessions/${sessionId}/exec" -H "Content-Type: application/json" -d @${reqFile} --max-time ${Math.ceil(timeoutMs / 1000)}`,
      timeoutMs: timeoutMs + 5000
    })

    const raw = r.stdout ?? ''
    let resp: any
    try {
      resp = JSON.parse(raw)
    } catch {
      return { stdout: '', stderr: `Invalid response: ${raw.slice(0, 200)}`, exitCode: -1, blocked: false }
    }

    const exitCode = resp.result?.exit_code ?? -1
    const stdout = resp.result?.stdout ?? ''
    const stderr = resp.result?.stderr ?? ''
    const errorCode = resp.result?.error?.code
    const guidanceRule = resp.guidance?.policy_rule
    const blockedOps = resp.events?.blocked_operations || []
    const blockedRule = blockedOps[0]?.policy?.rule
    const rule = guidanceRule || blockedRule || undefined
    const blocked = !!(guidanceRule || blockedRule) || errorCode === 'E_POLICY_DENIED'

    return { stdout, stderr, exitCode, blocked, rule }
  }

  private needsShell(command: string): boolean {
    let unquoted = ''
    let sq = false, dq = false
    for (const ch of command) {
      if (ch === "'" && !dq) { sq = !sq; continue }
      if (ch === '"' && !sq) { dq = !dq; continue }
      if (!sq && !dq) unquoted += ch
    }
    return /[|&;><$`(){}~*?\\]/.test(unquoted)
  }

  private parseCommand(input: string): { cmd: string, args: string[] } | null {
    const tokens: string[] = []
    let cur = ''
    let sq = false, dq = false
    for (const ch of input) {
      if (ch === "'" && !dq) { sq = !sq; continue }
      if (ch === '"' && !sq) { dq = !dq; continue }
      if (ch === ' ' && !sq && !dq) {
        if (cur) { tokens.push(cur); cur = '' }
      } else {
        cur += ch
      }
    }
    if (cur) tokens.push(cur)
    if (!tokens.length || sq || dq) return null
    return { cmd: tokens[0], args: tokens.slice(1) }
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
        console.log('PASS')
      } else {
        console.log(`FAIL (exit=${r.exitCode}, blocked=${r.blocked}, stdout=${r.stdout.slice(0, 80)})`)
      }
      return pass
    } catch (err) {
      const msg = err instanceof Error ? err.message : String(err)
      console.log(`ERROR: ${msg}`)
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
      .aptDeps('ca-certificates', 'curl', 'jq', 'libseccomp2', 'sudo', 'fuse3', 'python3', 'file', 'sqlite3')
      .additionalFiles({
        '/opt/install-agentsh.sh': {
          content: [
            '#!/bin/bash',
            'set -eux',
            `curl -fsSL -L "${url}" -o /tmp/agentsh.deb`,
            'dpkg -i /tmp/agentsh.deb',
            'rm -f /tmp/agentsh.deb',
            'agentsh --version',
            'mkdir -p /etc/agentsh/policies /var/lib/agentsh/quarantine /var/lib/agentsh/sessions /var/log/agentsh /home/user',
            'chmod 755 /etc/agentsh /etc/agentsh/policies /var/lib/agentsh /var/lib/agentsh/quarantine /var/lib/agentsh/sessions /var/log/agentsh',
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
        '/etc/environment': {
          content: [
            'AGENTSH_SERVER=http://127.0.0.1:18080',
            'AGENTSH_SHIM_FORCE=1',
          ].join('\n'),
        },
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
