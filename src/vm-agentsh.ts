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
        if ((r.stdout ?? '').trim() === 'ok') return
      } catch {
        // ignore — server not ready yet
      }
      await new Promise(res => setTimeout(res, intervalMs))
    }
    // Try to get server logs for diagnostics
    let logs = ''
    try {
      const r = await this.vm.exec('tail -20 /var/log/agentsh/server.log 2>/dev/null || echo "no logs"')
      logs = r.stdout ?? ''
    } catch {
      // ignore
    }
    throw new Error(`agentsh server not ready after ${retries * intervalMs / 1000}s. Logs:\n${logs}`)
  }

  async exec(command: string, timeoutMs = 30000): Promise<ExecResult> {
    const r = await this.vm.exec({ command, timeoutMs })
    return {
      stdout: r.stdout ?? '',
      stderr: r.stderr ?? '',
      exitCode: r.statusCode ?? -1,
      blocked: r.statusCode === 126,
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
      .aptDeps('ca-certificates', 'curl', 'jq', 'libseccomp2', 'sudo', 'fuse3')
      .additionalFiles({
        '/opt/install-agentsh.sh': {
          content: [
            '#!/bin/bash',
            'set -eux',
            `curl -fsSL -L "${url}" -o /tmp/agentsh.deb`,
            'dpkg -i /tmp/agentsh.deb',
            'rm -f /tmp/agentsh.deb',
            'agentsh --version',
            'mkdir -p /etc/agentsh/policies /var/lib/agentsh/quarantine /var/lib/agentsh/sessions /var/log/agentsh',
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
