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

    async function runDirect(desc: string, cmd: string, args: string[]): Promise<void> {
      const r = await agentsh.execDirect(cmd, args)
      if (r.blocked) {
        const rule = r.rule ? ` [${r.rule}]` : ''
        console.log(`  \u2717 BLOCKED: ${desc}${rule}`)
      } else if (r.exitCode !== 0) {
        console.log(`  \u2717 DENIED: ${desc} (exit: ${r.exitCode})`)
      } else {
        console.log(`  \u26a0 ALLOWED: ${desc}`)
      }
    }

    async function run(desc: string, cmd: string): Promise<void> {
      const r = await agentsh.exec(cmd)
      if (r.blocked) {
        console.log(`  \u2717 BLOCKED: ${desc}`)
      } else if (r.exitCode !== 0) {
        console.log(`  \u2717 DENIED: ${desc} (exit: ${r.exitCode})`)
      } else {
        console.log(`  \u26a0 ALLOWED: ${desc}`)
      }
    }

    console.log('='.repeat(60))
    console.log('MULTI-CONTEXT COMMAND EXECUTION DEMO')
    console.log('='.repeat(60))
    console.log()
    console.log('This demo shows how command_rules are enforced at the')
    console.log('session API boundary. Direct commands (execDirect) are')
    console.log('evaluated against policy. Commands within a bash session')
    console.log('run as sub-processes and rely on OS-level restrictions.')

    // Section 1: Direct API blocking (baseline)
    printSection('1. DIRECT API BLOCKING (baseline)')
    console.log('Commands sent directly to session API \u2192 command_rules evaluated:\n')
    await runDirect('sudo whoami', 'sudo', ['whoami'])
    await runDirect('ssh localhost', 'ssh', ['localhost'])
    await runDirect('kill -9 1', 'kill', ['-9', '1'])
    await runDirect('rm -rf /tmp/test', 'rm', ['-rf', '/tmp/test'])

    // Section 2: Same commands via bash shell
    printSection('2. SAME COMMANDS VIA BASH SHELL')
    console.log('Commands wrapped in bash.real \u2014 API sees bash.real, not the sub-command.')
    console.log('Sub-commands rely on OS restrictions (permissions, missing binaries):\n')
    await run('sudo whoami', 'sudo whoami 2>&1')
    await run('ssh localhost', 'ssh localhost 2>&1')
    await run('kill -9 1', 'kill -9 1 2>&1')

    // Section 3: Via env, xargs, find -exec
    printSection('3. INDIRECT EXECUTION CONTEXTS')
    console.log('Commands launched via env, xargs, find -exec:\n')
    await run('env sudo whoami', 'env sudo whoami 2>&1')
    await run('echo whoami | xargs sudo', 'echo whoami | xargs sudo 2>&1')
    await run('find -exec sudo whoami', 'find /tmp -maxdepth 0 -exec sudo whoami \\; 2>&1')

    // Section 4: Via nested script
    printSection('4. VIA NESTED SCRIPT')
    await agentsh.exec('printf "#!/bin/sh\\nsudo whoami\\n" > /tmp/escalate.sh && chmod +x /tmp/escalate.sh')
    await run('/tmp/escalate.sh (calls sudo)', '/tmp/escalate.sh 2>&1')

    // Section 5: Via Python subprocess
    printSection('5. VIA PYTHON subprocess')
    await run('python3 subprocess.run sudo', 'python3 -c "import subprocess; subprocess.run([\'sudo\',\'whoami\'])" 2>&1')
    await run('python3 os.system sudo', 'python3 -c "import os; os.system(\'sudo whoami\')" 2>&1')

    // Section 6: Allowed safe commands (non-over-blocking)
    async function runSafe(desc: string, cmd: string): Promise<void> {
      const r = await agentsh.exec(cmd)
      if (r.blocked) {
        console.log(`  \u2717 OVER-BLOCKED: ${desc}`)
      } else if (r.exitCode !== 0) {
        console.log(`  \u2717 FAILED: ${desc} (exit: ${r.exitCode})`)
      } else {
        console.log(`  \u2713 ALLOWED: ${desc}`)
      }
    }

    printSection('6. ALLOWED SAFE COMMANDS (no over-blocking)')
    console.log('Safe commands via same indirect contexts should succeed:\n')
    await runSafe('env whoami', 'env whoami')
    await runSafe('env ls /home', 'env ls /home')
    await runSafe('echo found | xargs echo', 'echo found | xargs echo')
    await runSafe('find -exec echo found', 'find /tmp -maxdepth 0 -exec echo found \\;')
    await runSafe('python3 subprocess echo', 'python3 -c "import subprocess; subprocess.run([\'echo\',\'allowed\'])" 2>&1')

    // Summary
    console.log('\n' + '='.repeat(60))
    console.log('SUMMARY')
    console.log('='.repeat(60))
    console.log(`
Command enforcement model:

  DIRECT API (execDirect):
    \u2717 sudo, ssh, kill, rm -rf  \u2192 command_rules evaluated, blocked

  WITHIN BASH (exec / indirect contexts):
    Commands run as sub-processes inside bash.real.
    The session API only evaluates the top-level command (bash.real).
    Sub-command blocking relies on:
      - Shell shim intercepts (when sub-process invokes /bin/bash)
      - OS-level permissions (sudo needs sudoers, kill needs privileges)
      - Missing binaries (ssh may not be installed)

  SAFE COMMANDS:
    \u2713 env, xargs, find -exec with safe commands \u2192 not over-blocked

  For full sub-process enforcement across all contexts,
  Landlock filesystem restrictions would prevent execution of
  blocked binaries regardless of how they are invoked.
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
