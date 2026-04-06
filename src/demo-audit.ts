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

    console.log('='.repeat(60))
    console.log('DEMONSTRATING AGENTSH AUDIT TRAIL')
    console.log('='.repeat(60))

    // Phase 1: Generate audit events
    printSection('Phase 1: Generating audit events')

    const commands = [
      { desc: 'Allowed: echo', cmd: 'echo audit-test' },
      { desc: 'Allowed: pwd', cmd: 'pwd' },
      { desc: 'Allowed: ls', cmd: 'ls /home' },
      { desc: 'Blocked: sudo', cmd: 'sudo whoami 2>&1' },
      { desc: 'Blocked: ssh', cmd: 'ssh localhost 2>&1' },
      { desc: 'Allowed: date', cmd: 'date' },
      { desc: 'Blocked: kill', cmd: 'kill -9 1 2>&1' },
      { desc: 'Allowed: cat', cmd: 'cat /etc/hostname' },
      { desc: 'Blocked: rm -rf', cmd: 'rm -rf /tmp/test 2>&1' },
      { desc: 'Allowed: python3', cmd: "python3 -c 'print(\"audit-ok\")'" },
    ]

    for (const { desc, cmd } of commands) {
      const r = await agentsh.exec(cmd)
      const status = r.blocked ? '\u2717 BLOCKED' : (r.exitCode === 0 ? '\u2713 ALLOWED' : '\u2717 FAILED')
      console.log(`  ${status}: ${desc}`)
    }

    // Small delay for events to be persisted
    await new Promise(r => setTimeout(r, 1000))

    // Phase 2: Query SQLite audit database
    printSection('Phase 2: Querying audit database (SQLite)')

    const dbPath = '/var/lib/agentsh/events.db'

    // Count total events
    const countResult = await agentsh.exec(`sqlite3 ${dbPath} "SELECT COUNT(*) FROM events" 2>&1`)
    console.log(`  Total audit events: ${countResult.stdout.trim()}`)

    // Show recent events
    const recentResult = await agentsh.exec(
      `sqlite3 -json ${dbPath} "SELECT * FROM events ORDER BY created_at DESC LIMIT 10" 2>&1`
    )
    if (recentResult.exitCode === 0 && recentResult.stdout.trim()) {
      try {
        const events = JSON.parse(recentResult.stdout)
        console.log(`\n  Recent events (last 10):`)
        for (const event of events) {
          const time = event.created_at || event.timestamp || 'unknown'
          const action = event.action || event.type || 'unknown'
          const command = event.command || event.path || event.details || ''
          const decision = event.decision || event.result || ''
          console.log(`    [${time}] ${action}: ${command} -> ${decision}`)
        }
      } catch {
        console.log(`  Raw output: ${recentResult.stdout.slice(0, 500)}`)
      }
    } else {
      console.log(`  SQLite query output: ${recentResult.stdout.slice(0, 500)}`)
      console.log(`  (Note: SQLite output format may vary based on agentsh schema)`)
    }

    // Show blocked events specifically
    const blockedResult = await agentsh.exec(
      `sqlite3 -json ${dbPath} "SELECT * FROM events WHERE decision='deny' OR decision='block' ORDER BY created_at DESC LIMIT 5" 2>&1`
    )
    if (blockedResult.exitCode === 0 && blockedResult.stdout.trim()) {
      console.log(`\n  Blocked events:`)
      try {
        const events = JSON.parse(blockedResult.stdout)
        for (const event of events) {
          const rule = event.rule || event.policy_rule || ''
          const command = event.command || event.path || ''
          console.log(`    \u2717 ${command} (rule: ${rule})`)
        }
      } catch {
        console.log(`  ${blockedResult.stdout.slice(0, 300)}`)
      }
    }

    // Phase 3: Query via agentsh CLI
    printSection('Phase 3: Querying via agentsh CLI')

    const eventsResult = await agentsh.exec('agentsh events 2>&1')
    if (eventsResult.exitCode === 0) {
      const lines = eventsResult.stdout.split('\n').slice(0, 15)
      console.log('  Recent events via CLI:')
      for (const line of lines) {
        if (line.trim()) console.log(`    ${line}`)
      }
      if (eventsResult.stdout.split('\n').length > 15) {
        console.log('    ... (truncated)')
      }
    } else {
      console.log(`  agentsh events: ${eventsResult.stdout.slice(0, 300)}`)
    }

    // Summary
    console.log('\n' + '='.repeat(60))
    console.log('SUMMARY')
    console.log('='.repeat(60))
    console.log(`
Audit trail capabilities:

\u2713 All command executions logged to SQLite database
\u2713 Events include: timestamp, command, decision, policy rule
\u2713 Blocked events tracked with specific rule that triggered
\u2713 Queryable via sqlite3 CLI for custom analysis
\u2713 Queryable via agentsh events CLI for quick review
\u2713 Database at: ${dbPath}
\u2713 Retention: 90 days (configured in config.yaml)
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
