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

    // Phase 1: Generate audit events via direct API (command_rules enforced)
    printSection('Phase 1: Generating audit events')

    const directCmds = [
      { desc: 'Allowed: echo', cmd: 'echo', args: ['audit-test'] },
      { desc: 'Allowed: ls', cmd: 'ls', args: ['/home'] },
      { desc: 'Allowed: date', cmd: 'date', args: [] },
      { desc: 'Allowed: cat', cmd: 'cat', args: ['/etc/hostname'] },
      { desc: 'Blocked: sudo', cmd: 'sudo', args: ['whoami'] },
      { desc: 'Blocked: ssh', cmd: 'ssh', args: ['localhost'] },
      { desc: 'Blocked: kill', cmd: 'kill', args: ['-9', '1'] },
      { desc: 'Blocked: rm -rf', cmd: 'rm', args: ['-rf', '/tmp/test'] },
    ]

    for (const { desc, cmd, args } of directCmds) {
      const r = await agentsh.execDirect(cmd, args)
      const rule = r.rule ? ` [${r.rule}]` : ''
      const status = r.blocked ? `\u2717 BLOCKED${rule}` : (r.exitCode === 0 ? '\u2713 ALLOWED' : '\u2717 FAILED')
      console.log(`  ${status}: ${desc}`)
    }

    // Small delay for events to be persisted
    await new Promise(r => setTimeout(r, 1000))

    // Phase 2: Discover database schema and query
    printSection('Phase 2: Querying audit database (SQLite)')

    const dbPath = '/var/lib/agentsh/events.db'

    // Show schema
    const schemaResult = await agentsh.exec(`sqlite3 ${dbPath} ".schema" 2>&1`)
    if (schemaResult.stdout.trim()) {
      console.log('  Database schema:')
      for (const line of schemaResult.stdout.trim().split('\n').slice(0, 10)) {
        console.log(`    ${line}`)
      }
    }

    // Get table names
    const tablesResult = await agentsh.exec(`sqlite3 ${dbPath} ".tables" 2>&1`)
    console.log(`\n  Tables: ${tablesResult.stdout.trim()}`)

    // Count total events
    const countResult = await agentsh.exec(`sqlite3 ${dbPath} "SELECT COUNT(*) FROM events" 2>&1`)
    console.log(`  Total audit events: ${countResult.stdout.trim()}`)

    // Show recent events using generic ORDER BY rowid
    const recentResult = await agentsh.exec(
      `sqlite3 -header -column ${dbPath} "SELECT * FROM events ORDER BY rowid DESC LIMIT 10" 2>&1`
    )
    if (recentResult.exitCode === 0 && recentResult.stdout.trim()) {
      console.log(`\n  Recent events (last 10):`)
      for (const line of recentResult.stdout.trim().split('\n').slice(0, 15)) {
        console.log(`    ${line.slice(0, 120)}`)
      }
    } else {
      console.log(`  Query result: ${recentResult.stdout.slice(0, 300)}`)
    }

    // Phase 3: Query via agentsh CLI
    printSection('Phase 3: Querying via agentsh CLI')

    const queryResult = await agentsh.exec('agentsh events query --direct-db --limit 10 2>&1')
    if (queryResult.exitCode === 0 && queryResult.stdout.trim()) {
      console.log('  Recent events via CLI:')
      for (const line of queryResult.stdout.trim().split('\n').slice(0, 15)) {
        if (line.trim()) console.log(`    ${line.slice(0, 120)}`)
      }
    } else {
      // Fallback to basic help
      const helpResult = await agentsh.exec('agentsh events query --help 2>&1')
      console.log('  agentsh events query usage:')
      for (const line of helpResult.stdout.trim().split('\n').slice(0, 10)) {
        if (line.trim()) console.log(`    ${line}`)
      }
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
\u2713 Queryable via agentsh events CLI
\u2713 Database at: ${dbPath}
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
