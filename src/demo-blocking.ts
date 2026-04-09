import 'dotenv/config'
import { freestyle, VmSpec } from 'freestyle-sandboxes'
import { VmAgentsh } from './vm-agentsh.js'
import { printSection } from './helpers.js'

async function main() {
  console.log('Creating Freestyle VM with agentsh...')
  const spec = new VmSpec().with('agentsh', new VmAgentsh())
  const { vm } = await freestyle.vms.create(spec)
  const agentsh = vm.agentsh

  try {
    await agentsh.waitReady()

    // Helper for shell commands (allowed commands, diagnostics, filesystem tests)
    async function run(description: string, command: string): Promise<boolean> {
      console.log(`\n--- ${description} ---`)
      const r = await agentsh.exec(command)
      if (r.blocked) {
        const ruleInfo = r.rule ? ` [${r.rule}]` : ''
        console.log(`\u2717 BLOCKED${ruleInfo}`)
        return false
      } else if (r.exitCode === 0) {
        console.log(`\u2713 ALLOWED`)
        return true
      } else {
        console.log(`\u2717 DENIED (exit: ${r.exitCode})`)
        return false
      }
    }

    // Helper for direct API calls (command policy enforcement tests)
    async function runDirect(description: string, command: string, args: string[] = []): Promise<boolean> {
      console.log(`\n--- ${description} ---`)
      const r = await agentsh.execDirect(command, args)
      if (r.blocked) {
        const ruleInfo = r.rule ? ` [${r.rule}]` : ''
        console.log(`\u2717 BLOCKED${ruleInfo}`)
        return false
      } else if (r.exitCode === 0) {
        console.log(`\u2713 ALLOWED`)
        return true
      } else {
        console.log(`\u2717 DENIED (exit: ${r.exitCode})`)
        return false
      }
    }

    console.log('='.repeat(60))
    console.log('DEMONSTRATING AGENTSH POLICY BLOCKING')
    console.log('='.repeat(60))

    // Section 1: Allowed commands
    printSection('1. ALLOWED COMMANDS')
    console.log('(Commands that pass policy)')
    await run('echo Hello', 'echo Hello')
    await run('pwd', 'pwd')
    await run('id', 'id')
    await run('ls /home', 'ls /home')
    await run('date', 'date')
    await run('python3 -c print(1)', "python3 -c 'print(1)'")
    await run('git --version', 'git --version')
    await run('agentsh --version', 'agentsh --version')

    // Section 2: Diagnostics
    printSection('2. DIAGNOSTICS')
    console.log('(Verify security subsystems are active)')
    await run('HTTPS_PROXY is set', 'echo $HTTPS_PROXY')
    await run('FUSE mounted', 'mount | grep agentsh || echo "FUSE NOT MOUNTED (deferred until first exec)"')
    await run('BASH_ENV active', 'echo $BASH_ENV')
    await run('kill builtin disabled', 'type kill 2>&1')
    await run('Read system binary (stat)', 'stat /usr/bin/ls')

    // Section 3: Privilege Escalation (blocked)
    printSection('3. BLOCKED: Privilege Escalation')
    await runDirect('sudo whoami', 'sudo', ['whoami'])
    await runDirect('su -', 'su', ['-'])
    await runDirect('chroot /', 'chroot', ['/'])

    // Section 4: Network Tools (blocked)
    printSection('4. BLOCKED: Network Tools')
    await runDirect('ssh localhost', 'ssh', ['localhost'])
    await runDirect('nc -h', 'nc', ['-h'])
    await runDirect('netcat -h', 'netcat', ['-h'])

    // Section 5: System Commands (blocked)
    printSection('5. BLOCKED: System Commands')
    await runDirect('kill -9 1', 'kill', ['-9', '1'])
    await runDirect('shutdown now', 'shutdown', ['now'])
    await runDirect('systemctl status', 'systemctl', ['status'])

    // Section 6: Recursive Delete (blocked)
    printSection('6. BLOCKED: Recursive Delete')
    await agentsh.exec('mkdir -p /tmp/test && touch /tmp/test/file.txt')
    await runDirect('rm -rf /tmp/test', 'rm', ['-rf', '/tmp/test'])
    await agentsh.exec('mkdir -p /tmp/test && touch /tmp/test/file.txt')
    await runDirect('rm -r /tmp/test', 'rm', ['-r', '/tmp/test'])
    await agentsh.exec('mkdir -p /tmp/test && touch /tmp/test/file.txt')
    await runDirect('rm --recursive /tmp/test', 'rm', ['--recursive', '/tmp/test'])

    // Section 7: Single File Delete (allowed)
    printSection('7. ALLOWED: Single File Delete')
    await agentsh.exec('mkdir -p /tmp/test && touch /tmp/test/file.txt')
    await runDirect('rm /tmp/test/file.txt (single)', 'rm', ['/tmp/test/file.txt'])

    // Section 8: Workspace Access (allowed)
    printSection('8. FILESYSTEM: Workspace Access (allowed)')
    await runDirect('Write to workspace', 'python3', ['-c', "open('/home/user/test-fs.txt','w').write('hello\\n')"])
    await runDirect('Read from workspace', 'cat', ['/home/user/test-fs.txt'])
    await runDirect('List workspace', 'ls', ['/home/user/test-fs.txt'])

    // Section 9: System paths (FUSE covers workspace only; Landlock not available)
    printSection('9. FILESYSTEM: System path access')
    console.log('(Note: file_rules for system paths require Landlock, not available on this kernel)')
    console.log('(FUSE intercepts workspace paths; system paths protected by OS-level perms only)')
    await runDirect('Read /etc/hosts (allowed)', 'cat', ['/etc/hosts'])
    await runDirect('Read /sys/kernel/hostname', 'cat', ['/sys/kernel/hostname'])

    // Section 10: Credential Access (file doesn't exist → error)
    printSection('10. FILESYSTEM: Credential access')
    console.log('(Approve-required paths — files do not exist, so access fails)')
    await runDirect('Read ~/.ssh/id_rsa', 'cat', ['/home/user/.ssh/id_rsa'])
    await runDirect('Read ~/.aws/credentials', 'cat', ['/home/user/.aws/credentials'])
    await runDirect('Read .env file', 'cat', ['/home/user/.env'])

    // Section 11: Soft-delete
    printSection('11. FILESYSTEM: Soft-delete in workspace')
    await runDirect('Create file', 'python3', ['-c', "open('/home/user/soft-del.txt','w').write('important\\n')"])
    await runDirect('Delete workspace file (soft-delete)', 'rm', ['/home/user/soft-del.txt'])
    await runDirect('Verify original path gone', 'ls', ['/home/user/soft-del.txt'])

    // Summary
    console.log('\n' + '='.repeat(60))
    console.log('SUMMARY')
    console.log('='.repeat(60))
    console.log(`
agentsh policy enforcement on Freestyle VM (80/100 protection score):

COMMAND BLOCKING (via session API command_rules):
  \u2717 sudo, su, chroot    \u2192 block-shell-escape
  \u2717 ssh, nc, netcat     \u2192 block-network-tools
  \u2717 kill, shutdown      \u2192 block-system-commands
  \u2717 rm -r, rm -rf       \u2192 block-rm-recursive

FILESYSTEM (via FUSE workspace overlay):
  \u2713 Workspace read/write \u2192 allow-workspace-read/write
  \u2713 Workspace delete     \u2192 soft-delete-workspace (quarantined)
  \u2713 /tmp/**              \u2192 allow-tmp

KERNEL CAPABILITIES:
  \u2713 seccomp-execve       \u2192 command interception
  \u2713 FUSE                 \u2192 workspace file interception
  \u2713 cgroups-v2           \u2192 resource limits (via base_path override, see #197)
  \u2713 capability-drop      \u2192 privilege reduction
  \u2713 CAP_BPF (present)    \u2192 server has cap_bpf; raw bpf() works
  \u2717 Landlock             \u2192 not in kernel (would add full filesystem policy)
  \u2717 eBPF backend         \u2192 disabled — agentsh detect bug (canyonroad/agentsh#196)
                             kernel supports it, but agentsh refuses to start
                             with ebpf.enabled=true. Verify: npm run diag:kernel
`)

  } catch (error) {
    console.error('Error:', error)
  } finally {
    console.log('\nCleaning up...')
    try { await vm.stop() } catch {}
    console.log('Done.')
  }
}

main().catch(console.error)
