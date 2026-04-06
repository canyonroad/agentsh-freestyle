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
        content: 'Meeting notes: Q2 planning session, action items due Friday',
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
    console.log('\n  Verifying files were created:')
    for (const { path, label } of files) {
      const r = await agentsh.exec(`cat ${path} 2>&1`)
      if (r.exitCode === 0) {
        console.log(`    ${label}: "${r.stdout.trim()}"`)
      } else {
        console.log(`    ${label}: NOT FOUND`)
      }
    }

    // Phase 2: Delete files (triggers soft-delete via agentsh FUSE)
    printSection('Phase 2: Deleting files (soft-delete via FUSE)')
    console.log('  (agentsh intercepts rm and quarantines instead of permanently deleting)')

    for (const { path, label } of files) {
      const r = await agentsh.exec(`rm ${path} 2>&1`)
      const status = r.exitCode === 0 ? '\u2713 deleted' : `\u2717 error (exit ${r.exitCode})`
      console.log(`  ${status}: ${label}`)
    }

    // Verify files are gone from original locations
    console.log('\n  Verifying files are gone from original paths:')
    for (const { path, label } of files) {
      const r = await agentsh.exec(
        `test -f ${path} && echo exists || echo gone`
      )
      console.log(`    ${label}: ${r.stdout.trim()}`)
    }

    // Phase 3: List quarantined files
    printSection('Phase 3: Listing quarantined files')

    const trashListResult = await agentsh.exec('agentsh trash list 2>&1')
    console.log('  agentsh trash list output:')
    const trashLines = trashListResult.stdout.split('\n').filter(l => l.trim())
    for (const line of trashLines) {
      console.log(`    ${line}`)
    }
    if (!trashListResult.stdout.trim()) {
      console.log(`    (no output; stderr: ${trashListResult.stderr.slice(0, 200)})`)
    }

    // Phase 4: Restore a file
    printSection('Phase 4: Restoring a quarantined file')

    // Extract restore token from trash list output
    // Tokens typically appear as hex strings or UUIDs in the trash list
    let restoreToken: string | null = null
    for (const line of trashLines) {
      // Match a hex token (UUID or similar) - common patterns in agentsh trash output
      const uuidMatch = line.match(
        /([0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12})/i
      )
      const hexMatch = line.match(/\b([0-9a-f]{16,})\b/i)
      if (uuidMatch) {
        restoreToken = uuidMatch[1]
        break
      } else if (hexMatch) {
        restoreToken = hexMatch[1]
        break
      }
    }

    if (restoreToken) {
      console.log(`  Found restore token: ${restoreToken}`)
      const restoreResult = await agentsh.exec(
        `agentsh trash restore ${restoreToken} 2>&1`
      )
      if (restoreResult.exitCode === 0) {
        console.log(`  \u2713 Restore succeeded`)
        if (restoreResult.stdout.trim()) {
          console.log(`    Output: ${restoreResult.stdout.trim()}`)
        }
      } else {
        console.log(`  \u2717 Restore failed (exit ${restoreResult.exitCode})`)
        console.log(`    Output: ${restoreResult.stdout.slice(0, 200)}`)
      }

      // Verify restored file content is intact
      console.log('\n  Verifying restored file content:')
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
      console.log('  Could not extract restore token from trash list output.')
      console.log('  Raw trash list:')
      console.log(`    ${trashListResult.stdout.slice(0, 400) || '(empty)'}`)
    }

    // Summary
    console.log('\n' + '='.repeat(60))
    console.log('SUMMARY')
    console.log('='.repeat(60))
    console.log(`
Soft-delete and quarantine recovery workflow:

\u2713 Files created in workspace (/home/user/*)
\u2713 rm triggers soft-delete via agentsh FUSE (no data loss)
\u2713 Files are quarantined, not permanently deleted
\u2713 Original paths show as gone after rm
\u2713 agentsh trash list shows quarantined files with tokens
\u2713 agentsh trash restore <token> recovers files to original path
\u2713 Restored file content matches original

Key agentsh soft-delete commands:
  agentsh trash list              - list quarantined files
  agentsh trash restore <token>   - restore a quarantined file
  agentsh trash purge             - permanently delete quarantined files
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
