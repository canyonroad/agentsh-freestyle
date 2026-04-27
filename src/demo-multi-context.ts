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

    async function runShell(desc: string, script: string): Promise<void> {
      const r = await agentsh.execDirect('/bin/bash.real', ['-c', script])
      if (r.blocked) {
        const rule = r.rule ? ` [${r.rule}]` : ''
        console.log(`  \u2717 BLOCKED: ${desc}${rule}`)
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
    console.log('This demo shows how command_rules are enforced across')
    console.log('direct session API calls, derived bash -c payloads, and')
    console.log('opaque shell scripts in agentsh v0.18.3.')

    // Section 1: Direct API blocking (baseline)
    printSection('1. DIRECT API BLOCKING (baseline)')
    console.log('Commands sent directly to session API \u2192 command_rules evaluated:\n')
    await runDirect('sudo whoami', 'sudo', ['whoami'])
    await runDirect('ssh localhost', 'ssh', ['localhost'])
    await runDirect('kill -9 1', 'kill', ['-9', '1'])
    await runDirect('rm -rf /tmp/test', 'rm', ['-rf', '/tmp/test'])

    // Section 2: Same commands via bash shell
    printSection('2. SAME COMMANDS VIA BASH SHELL')
    console.log('Simple bash -c payloads are derived and checked against command_rules:\n')
    await runShell('sudo whoami', 'sudo whoami')
    await runShell('ssh localhost', 'ssh localhost')
    await runShell('kill -9 1', 'kill -9 1')

    // Section 3: Via env, xargs, find -exec
    printSection('3. INDIRECT EXECUTION CONTEXTS')
    console.log('Commands launched via env, xargs, find -exec:\n')
    await runShell('env sudo whoami', 'env sudo whoami')
    await runShell('echo whoami | xargs sudo (opaque)', 'echo whoami | xargs sudo')
    await runDirect('find -exec sudo whoami', 'find', ['/tmp', '-maxdepth', '0', '-exec', 'sudo', 'whoami', ';'])

    // Section 4: Via nested script
    printSection('4. VIA NESTED SCRIPT')
    await agentsh.execDirect('python3', ['-c', "open('/tmp/escalate.sh','w').write('#!/bin/sh\\nsudo whoami\\n')"])
    await agentsh.execDirect('chmod', ['+x', '/tmp/escalate.sh'])
    await runDirect('/tmp/escalate.sh (calls sudo)', '/tmp/escalate.sh', [])

    // Section 5: Via Python subprocess
    printSection('5. VIA PYTHON subprocess')
    await runDirect('python3 subprocess.run sudo', 'python3', ['-c', "import subprocess; subprocess.run(['sudo','whoami'])"])
    await runDirect('python3 os.system sudo', 'python3', ['-c', "import os; os.system('sudo whoami')"])

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
    await runShell('echo found | xargs echo (opaque)', 'echo found | xargs echo')
    await runDirect('find -exec echo found', 'find', ['/tmp', '-maxdepth', '0', '-exec', 'echo', 'found', ';'])
    await runDirect('python3 subprocess echo', 'python3', ['-c', "import subprocess; subprocess.run(['echo','allowed'])"])

    // Summary
    console.log('\n' + '='.repeat(60))
    console.log('SUMMARY')
    console.log('='.repeat(60))
    console.log(`
Command enforcement model:

  DIRECT API (execDirect):
    \u2717 sudo, ssh, kill, rm -rf  \u2192 command_rules evaluated, blocked

  WITHIN BASH (exec / indirect contexts):
    Simple bash -c payloads are derived and checked against command_rules.
    Opaque scripts with pipes, redirects, or command expansion fail closed
    as shellc-opaque-script under restrictive command policies.

  SAFE COMMANDS:
    \u2713 env, find -exec, python subprocess with safe commands \u2192 not over-blocked

  OPAQUE SCRIPTING:
    \u2717 shell pipelines and redirects are intentionally blocked unless the
      operator relaxes command policy to an allow-only command posture.
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
