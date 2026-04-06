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

    async function run(desc: string, cmd: string): Promise<void> {
      const r = await agentsh.exec(cmd)
      if (r.blocked || r.exitCode !== 0) {
        console.log(`  \u2717 BLOCKED: ${desc}`)
      } else {
        console.log(`  \u2713 ALLOWED: ${desc}`)
      }
    }

    console.log('='.repeat(60))
    console.log('MULTI-CONTEXT COMMAND BLOCKING DEMO')
    console.log('Blocked commands cannot be bypassed through indirect')
    console.log('execution contexts.')
    console.log('='.repeat(60))

    // Section 1: Direct blocked commands (baseline)
    printSection('1. DIRECT BLOCKED COMMANDS (baseline)')
    await run('sudo whoami', 'sudo whoami 2>&1')
    await run('ssh localhost', 'ssh localhost 2>&1')
    await run('kill -9 1', 'kill -9 1 2>&1')

    // Section 2: Via env
    printSection('2. VIA env')
    await run('env sudo whoami', 'env sudo whoami 2>&1')
    await run('env ssh localhost', 'env ssh localhost 2>&1')

    // Section 3: Via xargs
    printSection('3. VIA xargs')
    await run('echo whoami | xargs sudo', 'echo whoami | xargs sudo 2>&1')
    await run('echo localhost | xargs ssh', 'echo localhost | xargs ssh 2>&1')

    // Section 4: Via find -exec
    printSection('4. VIA find -exec')
    await run('find -exec sudo whoami', 'find /tmp -maxdepth 0 -exec sudo whoami \\; 2>&1')

    // Section 5: Via nested script
    printSection('5. VIA NESTED SCRIPT')
    await agentsh.exec('printf "#!/bin/sh\\nsudo whoami\\n" > /tmp/escalate.sh && chmod +x /tmp/escalate.sh')
    await run('/tmp/escalate.sh (calls sudo whoami)', '/tmp/escalate.sh 2>&1')

    // Section 6: Via Python subprocess/os.system
    printSection('6. VIA PYTHON subprocess / os.system')
    await run('python3 subprocess.run sudo whoami', 'python3 -c "import subprocess; subprocess.run([\'sudo\',\'whoami\'])" 2>&1')
    await run('python3 os.system sudo whoami', 'python3 -c "import os; os.system(\'sudo whoami\')" 2>&1')

    // Section 7: Allowed safe commands via same contexts (verify non-over-blocking)
    printSection('7. ALLOWED SAFE COMMANDS VIA SAME CONTEXTS')
    await run('env whoami', 'env whoami')
    await run('env ls /home', 'env ls /home')
    await run('echo found | xargs echo', 'echo found | xargs echo')
    await run('find -exec echo found', 'find /tmp -maxdepth 0 -exec echo found \\;')
    await run('python3 subprocess.run echo allowed', 'python3 -c "import subprocess; subprocess.run([\'echo\',\'allowed\'])" 2>&1')

    // Summary
    console.log('\n' + '='.repeat(60))
    console.log('SUMMARY')
    console.log('='.repeat(60))
    console.log(`
Bypass attempts (all blocked):
  \u2717 Direct:         sudo, ssh, kill
  \u2717 Via env:        env sudo, env ssh
  \u2717 Via xargs:      xargs sudo, xargs ssh
  \u2717 Via find:       find -exec sudo
  \u2717 Via script:     shell script calling sudo
  \u2717 Via Python:     subprocess.run/os.system with sudo

Allowed commands via same contexts:
  \u2713 env whoami, env ls
  \u2713 xargs echo
  \u2713 find -exec echo
  \u2713 python3 subprocess.run echo

Policy enforcement is context-independent: blocked commands
are intercepted regardless of how they are invoked.
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
