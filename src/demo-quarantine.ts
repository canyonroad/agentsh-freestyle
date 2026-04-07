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
    console.log('DEMONSTRATING SOFT-DELETE AND QUARANTINE RECOVERY')
    console.log('='.repeat(60))

    // Phase 1: Create test files
    printSection('Phase 1: Creating test files')

    const files = [
      {
        path: '/home/user/important-doc.txt',
        content: 'Critical business data',
        label: 'important-doc.txt',
      },
      {
        path: '/home/user/config-backup.txt',
        content: 'database_url=postgres://admin:secret@db.internal:5432/prod',
        label: 'config-backup.txt',
      },
      {
        path: '/home/user/notes.txt',
        content: 'Meeting notes: Q2 planning session',
        label: 'notes.txt',
      },
    ]

    for (const { path, content, label } of files) {
      const r = await agentsh.exec(
        `python3 -c "open('${path}', 'w').write('${content}')"`
      )
      if (r.exitCode === 0) {
        console.log(`  \u2713 Created ${label}`)
      } else {
        console.log(`  \u2717 Failed to create ${label}: ${r.stderr.slice(0, 100)}`)
      }
    }

    // Verify files exist
    console.log('\n  Verifying files:')
    for (const { path, label } of files) {
      const r = await agentsh.exec(`cat ${path} 2>&1`)
      if (r.exitCode === 0) {
        console.log(`    ${label}: "${r.stdout.trim()}"`)
      } else {
        console.log(`    ${label}: NOT FOUND`)
      }
    }

    // Phase 2: Delete files
    printSection('Phase 2: Deleting files (soft-delete via FUSE)')
    console.log('  agentsh FUSE intercepts rm and quarantines instead of deleting.\n')

    for (const { path, label } of files) {
      const r = await agentsh.exec(`rm ${path} 2>&1`)
      const status = r.exitCode === 0 ? '\u2713 deleted (soft)' : `\u2717 error (exit ${r.exitCode})`
      console.log(`  ${status}: ${label}`)
    }

    // Verify files are gone
    console.log('\n  Verifying files are gone from original paths:')
    for (const { path, label } of files) {
      const r = await agentsh.exec(`test -f ${path} && echo exists || echo gone`)
      console.log(`    ${label}: ${r.stdout.trim()}`)
    }

    // Phase 3: List quarantined files
    printSection('Phase 3: Listing quarantined files')

    // Try agentsh trash list first
    const trashListResult = await agentsh.exec('agentsh trash list 2>&1')
    const trashOutput = trashListResult.stdout.trim()
    const trashLines = trashOutput.split('\n').filter(l => l.trim())

    console.log('  agentsh trash list:')
    if (trashOutput && !trashOutput.includes('empty') && trashLines.length > 0) {
      for (const line of trashLines) {
        console.log(`    ${line}`)
      }
    } else {
      console.log(`    Output: ${trashOutput || '(empty)'}`)
      console.log()
      console.log('  Investigating quarantine storage...')

      // Check quarantine directories
      const dirs = [
        '/var/lib/agentsh/quarantine',
      ]
      for (const dir of dirs) {
        const ls = await agentsh.exec(`ls -la ${dir}/ 2>&1`)
        console.log(`    ${dir}: ${ls.stdout.trim().split('\n').length} entries`)
        if (ls.stdout.trim() && !ls.stdout.includes('total 0')) {
          for (const line of ls.stdout.trim().split('\n').slice(0, 5)) {
            console.log(`      ${line}`)
          }
        }
      }

      // Check session-specific quarantine
      const sessionDirs = await agentsh.exec('find /var/lib/agentsh/sessions/ -name "quarantine" -type d 2>/dev/null')
      if (sessionDirs.stdout.trim()) {
        for (const dir of sessionDirs.stdout.trim().split('\n')) {
          const ls = await agentsh.exec(`ls -la ${dir.trim()}/ 2>&1`)
          console.log(`    ${dir.trim()}: ${ls.stdout.trim().split('\n').length} entries`)
          if (ls.stdout.trim() && !ls.stdout.includes('total 0')) {
            for (const line of ls.stdout.trim().split('\n').slice(0, 5)) {
              console.log(`      ${line}`)
            }
          }
        }
      }

      // Check FUSE mount to understand workspace-mnt path
      const mounts = await agentsh.exec('mount | grep agentsh 2>&1')
      if (mounts.stdout.trim()) {
        console.log(`    FUSE mount: ${mounts.stdout.trim()}`)
      }

      // Check audit log for delete events
      const schema = await agentsh.exec('sqlite3 /var/lib/agentsh/events.db ".schema events" 2>&1')
      if (schema.stdout.trim()) {
        console.log(`\n  Audit events schema: ${schema.stdout.trim().slice(0, 200)}`)
      }
      const auditDeletes = await agentsh.exec('sqlite3 /var/lib/agentsh/events.db "SELECT * FROM events ORDER BY rowid DESC LIMIT 5" 2>&1')
      if (auditDeletes.stdout.trim()) {
        console.log('\n  Recent audit events:')
        for (const line of auditDeletes.stdout.trim().split('\n').slice(0, 5)) {
          console.log(`    ${line.slice(0, 120)}`)
        }
      }
    }

    // Phase 4: Attempt restore
    printSection('Phase 4: Restoring a quarantined file')

    // Try to extract token from trash list
    let restoreToken: string | null = null
    for (const line of trashLines) {
      const uuidMatch = line.match(/([0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12})/i)
      const hexMatch = line.match(/\b([0-9a-f]{16,})\b/i)
      if (uuidMatch) { restoreToken = uuidMatch[1]; break }
      else if (hexMatch) { restoreToken = hexMatch[1]; break }
    }

    if (restoreToken) {
      console.log(`  Found restore token: ${restoreToken}`)
      const restoreResult = await agentsh.exec(`agentsh trash restore ${restoreToken} 2>&1`)
      if (restoreResult.exitCode === 0) {
        console.log(`  \u2713 Restore succeeded`)
        if (restoreResult.stdout.trim()) {
          console.log(`    Output: ${restoreResult.stdout.trim()}`)
        }
        // Verify restored content
        console.log('\n  Checking restored files:')
        for (const { path, content, label } of files) {
          const r = await agentsh.exec(`cat ${path} 2>&1`)
          if (r.exitCode === 0) {
            const intact = r.stdout.trim() === content
            const icon = intact ? '\u2713' : '~'
            console.log(`    ${icon} ${label}: "${r.stdout.trim()}"`)
          } else {
            console.log(`    - ${label}: not restored (still in quarantine)`)
          }
        }
      } else {
        console.log(`  \u2717 Restore failed (exit ${restoreResult.exitCode})`)
        console.log(`    ${restoreResult.stdout.slice(0, 200)}`)
      }
    } else {
      console.log('  No restore token found in trash list output.')
      console.log('  This may indicate FUSE soft-delete is storing files in a')
      console.log('  session-specific quarantine path. The files are preserved')
      console.log('  but the CLI may need session context to list them.')
    }

    // Summary
    console.log('\n' + '='.repeat(60))
    console.log('SUMMARY')
    console.log('='.repeat(60))
    console.log(`
Soft-delete and quarantine workflow:

  1. Files created in workspace (/home/user/*)
  2. rm triggers FUSE intercept \u2192 soft-delete
  3. Files removed from original path
  4. Files preserved in quarantine directory
  5. agentsh trash list \u2192 shows quarantined files
  6. agentsh trash restore <token> \u2192 recovers files

Key commands:
  agentsh trash list              - list quarantined files
  agentsh trash restore <token>   - restore a quarantined file
  agentsh trash purge             - permanently delete quarantined files

Note: FUSE soft-delete only applies to workspace paths.
Files deleted in /tmp or other paths are permanently removed.
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
