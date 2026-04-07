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

    async function run(desc: string, cmd: string): Promise<{ allowed: boolean; output: string }> {
      const r = await agentsh.exec(cmd)
      const output = r.stdout.trim()
      if (r.blocked) {
        console.log(`  \u2717 BLOCKED: ${desc}`)
        return { allowed: false, output }
      } else if (r.exitCode !== 0) {
        console.log(`  \u2717 DENIED: ${desc} (exit: ${r.exitCode})`)
        return { allowed: false, output }
      } else {
        console.log(`  \u2713 ALLOWED: ${desc}`)
        return { allowed: true, output }
      }
    }

    console.log('='.repeat(60))
    console.log('FUSE WORKSPACE FILE PROTECTION DEMO')
    console.log('='.repeat(60))
    console.log()
    console.log('agentsh mounts a FUSE overlay on the workspace directory.')
    console.log('All file operations within the workspace are intercepted.')
    console.log('Deletes are converted to soft-deletes (quarantine).')
    console.log()
    console.log('Note: FUSE covers the workspace path only. System paths')
    console.log('(/etc, /usr, /var) require Landlock for enforcement.')

    // 1. FUSE mount verification
    printSection('1. FUSE MOUNT VERIFICATION')
    await run('Check FUSE mount', 'mount | grep -E "agentsh|fuse" || echo "FUSE deferred (activates on first session exec)"')
    await run('Check /dev/fuse', 'ls -la /dev/fuse 2>&1')

    // 2. Workspace write/read
    printSection('2. WORKSPACE READ/WRITE (allowed)')
    console.log('Writes and reads to workspace path are allowed through FUSE:\n')
    await run('Write file via echo', 'echo "shell content" > /home/user/test-fuse.txt && echo ok')
    await run('Read file via cat', 'cat /home/user/test-fuse.txt')
    await run('Write via Python', "python3 -c \"open('/home/user/py-test.txt','w').write('python wrote this\\n')\" && echo ok")
    await run('Read via Python', "python3 -c \"print(open('/home/user/py-test.txt').read().strip())\"")
    await run('List workspace', 'ls /home/user/')

    // 3. Soft-delete
    printSection('3. SOFT-DELETE (workspace deletes quarantined)')
    console.log('Deleting a workspace file triggers soft-delete via FUSE.\n')
    await run('Create file', "python3 -c \"open('/home/user/to-delete.txt','w').write('important data\\n')\"")
    const { allowed: verifyOk } = await run('Verify exists', 'cat /home/user/to-delete.txt')
    await run('Delete file (soft-delete)', 'rm /home/user/to-delete.txt 2>&1 && echo ok')
    await run('Verify gone from path', 'test -f /home/user/to-delete.txt && echo exists || echo gone')
    console.log()
    console.log('  Checking quarantine:')
    const trashResult = await agentsh.exec('agentsh trash list 2>&1')
    const trashOutput = trashResult.stdout.trim()
    if (trashOutput) {
      for (const line of trashOutput.split('\n').filter(l => l.trim())) {
        console.log(`    ${line}`)
      }
    } else {
      console.log('    (trash list empty \u2014 checking quarantine directory directly)')
      const dirResult = await agentsh.exec('ls -la /var/lib/agentsh/quarantine/ 2>&1')
      console.log(`    Quarantine dir: ${dirResult.stdout.trim()}`)
      // Also check the session's quarantine path
      const sessionResult = await agentsh.exec('find /var/lib/agentsh/sessions/ -name "quarantine" -type d 2>/dev/null | head -3')
      if (sessionResult.stdout.trim()) {
        console.log(`    Session quarantine paths: ${sessionResult.stdout.trim()}`)
        for (const dir of sessionResult.stdout.trim().split('\n')) {
          const lsResult = await agentsh.exec(`ls -la ${dir.trim()}/ 2>&1`)
          console.log(`    Contents of ${dir.trim()}: ${lsResult.stdout.trim().split('\n').length} entries`)
        }
      }
    }

    // 4. /tmp access
    printSection('4. /tmp ACCESS (allowed, no FUSE overlay)')
    console.log('/tmp is writable but not FUSE-protected (no soft-delete):\n')
    await run('Write to /tmp', 'echo "tmp data" > /tmp/fuse-test.txt && echo ok')
    await run('Read from /tmp', 'cat /tmp/fuse-test.txt')
    await run('Delete from /tmp (permanent)', 'rm /tmp/fuse-test.txt && echo ok')
    await run('Verify permanently gone', 'test -f /tmp/fuse-test.txt && echo exists || echo gone')

    // 5. System paths
    printSection('5. SYSTEM PATH ACCESS (no FUSE coverage)')
    console.log('Without Landlock, system paths rely on OS permissions only.\n')
    await run('Read /etc/hostname', 'cat /etc/hostname')
    await run('Read /etc/hosts', 'cat /etc/hosts')
    await run('Write to /etc (OS perms)', 'echo "hack" > /etc/test_file 2>&1')
    await run('Write to /usr/bin (OS perms)', 'echo "hack" > /usr/bin/evil 2>&1')

    // Summary
    console.log('\n' + '='.repeat(60))
    console.log('FUSE WORKSPACE PROTECTION SUMMARY')
    console.log('='.repeat(60))
    console.log(`
FUSE provides workspace-level file interception:

  WORKSPACE (/home/user/**):
    \u2713 Read/write allowed and audited
    \u2713 Deletes converted to soft-delete (quarantine)
    \u2713 Python/language I/O intercepted at VFS level
    \u2713 All operations logged to audit trail

  /tmp/**:
    \u2713 Full access (not FUSE-protected)
    \u2717 Deletes are permanent (no soft-delete)

  SYSTEM PATHS (/etc, /usr, /var, /proc):
    \u26a0 Not covered by FUSE (workspace-scoped only)
    \u26a0 Rely on OS-level permissions
    \u2192 Landlock (CONFIG_SECURITY_LANDLOCK) would extend
      file_rules enforcement to all filesystem paths

  Soft-delete commands:
    agentsh trash list              - list quarantined files
    agentsh trash restore <token>   - restore a quarantined file
    agentsh trash purge             - permanently delete all
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
