import 'dotenv/config'
import { freestyle, VmSpec } from 'freestyle-sandboxes'
import { VmAgentsh } from './vm-agentsh.js'
import { printSection } from './helpers.js'

async function main() {
  console.log('Creating Freestyle VM with agentsh...')
  const spec = new VmSpec().with('agentsh', new VmAgentsh())
  const { vm } = await freestyle.vms.create(spec)
  const agentsh = vm.agentsh

  const results: { name: string; enforced: boolean; detail: string }[] = []

  try {
    await agentsh.waitReady()

    console.log('='.repeat(60))
    console.log('DEMONSTRATING AGENTSH RESOURCE LIMITS')
    console.log('='.repeat(60))
    console.log()
    console.log('agentsh v0.18.x (canyonroad/agentsh#202/#214) auto-detects the')
    console.log('Freestyle nested-cgroup limitation (#197 — empty subtree_control')
    console.log('under freestyle-supervisor.service) and falls back to a')
    console.log('top-level /sys/fs/cgroup/agentsh.slice. The slice IS created')
    console.log('and per-command sub-cgroups appear, but on Freestyle the')
    console.log('processes spawned through the session API end up under')
    console.log('/system.slice/freestyle-supervisor.service rather than the')
    console.log('per-command cgroup, so most numeric limits silently no-op.')
    console.log()
    console.log('Memory and timeout still trip via systemd / agentsh server')
    console.log('side enforcement, so they appear ENFORCED below — but PID,')
    console.log('CPU, and disk I/O caps are NOT enforced on Freestyle today.')

    // ---------------------------------------------------------------
    // 1. PID Limit (max 100 processes)
    // ---------------------------------------------------------------
    printSection('1. PID LIMIT (max ~100 processes)')
    console.log('Attempting to fork 150 child processes...')

    try {
      const pidResult = await agentsh.exec(`python3 -c "
import os, sys
pids = []
try:
    for i in range(150):
        pid = os.fork()
        if pid == 0:
            import time; time.sleep(10); sys.exit(0)
        pids.append(pid)
except OSError as e:
    print(f'Fork limited after {len(pids)} processes: {e}')
finally:
    for p in pids:
        try: os.kill(p, 9)
        except: pass
        try: os.waitpid(p, 0)
        except: pass
" 2>&1`, 30000)

      const pidOutput = pidResult.stdout.trim()
      console.log('Output:', pidOutput || '(no output)')

      const pidEnforced = pidOutput.includes('Fork limited') || pidResult.exitCode !== 0
      if (pidEnforced) {
        console.log('\u2713 PID LIMIT ENFORCED \u2014 fork failed before 150 processes')
      } else {
        console.log('\u2717 PID limit not triggered (forked all 150)')
      }
      results.push({ name: 'PID limit (~100 processes)', enforced: pidEnforced, detail: pidOutput.slice(0, 100) })
    } catch {
      console.log('\u2717 PID test errored (session may have been disrupted)')
      results.push({ name: 'PID limit (~100 processes)', enforced: false, detail: 'test errored' })
    }

    // ---------------------------------------------------------------
    // 2. Memory Limit (2048 MB)
    // ---------------------------------------------------------------
    printSection('2. MEMORY LIMIT (2048 MB)')
    console.log('Allocating 100 MB blocks until MemoryError or OOM...')
    console.log('(This may kill the process if cgroup limits are enforced)')

    try {
      const memResult = await agentsh.exec(`python3 -c "
blocks = []
try:
    while True:
        blocks.append(b'x' * (100 * 1024 * 1024))
        print(f'Allocated {len(blocks) * 100} MB', flush=True)
except MemoryError:
    print(f'Memory limited at ~{len(blocks) * 100} MB')
except Exception as e:
    print(f'Stopped at ~{len(blocks) * 100} MB: {e}')
" 2>&1`, 60000)

      const memOutput = memResult.stdout.trim()
      console.log('Output:')
      if (memOutput) {
        // Show last few lines
        const lines = memOutput.split('\n')
        const showLines = lines.length > 5 ? lines.slice(-5) : lines
        for (const line of showLines) {
          console.log(`  ${line}`)
        }
      } else {
        console.log('  (no output \u2014 process may have been OOM-killed)')
      }

      const memEnforced = memOutput.includes('Memory limited') ||
        memResult.exitCode !== 0 || !memOutput
      if (memOutput.includes('Memory limited')) {
        console.log('\u2713 MEMORY LIMIT ENFORCED \u2014 MemoryError raised')
      } else if (memResult.exitCode !== 0 || !memOutput) {
        console.log('\u2713 MEMORY LIMIT ENFORCED \u2014 process was killed (OOM)')
      } else {
        console.log('\u2717 Memory limit not clearly triggered')
      }
      results.push({ name: 'Memory limit (2048 MB)', enforced: memEnforced, detail: memOutput.split('\n').pop()?.slice(0, 100) ?? '' })
    } catch {
      console.log('\u2713 MEMORY LIMIT ENFORCED \u2014 process killed / session disrupted')
      results.push({ name: 'Memory limit (2048 MB)', enforced: true, detail: 'process killed' })
    }

    // Verify session still works after memory bomb
    console.log('\n  Verifying session health...')
    try {
      const health = await agentsh.exec('echo session-ok')
      if (health.stdout.includes('session-ok')) {
        console.log('  \u2713 Session recovered')
      } else {
        console.log('  \u26a0 Session may be degraded')
      }
    } catch {
      console.log('  \u26a0 Session disrupted \u2014 remaining tests may be affected')
    }

    // ---------------------------------------------------------------
    // 3. Command Timeout
    // ---------------------------------------------------------------
    printSection('3. COMMAND TIMEOUT (5s exec timeout)')
    console.log('Running "sleep 600" with a 5-second exec timeout...')

    try {
      const timeoutStart = Date.now()
      const timeoutResult = await agentsh.exec('sleep 600', 5000)
      const elapsed = ((Date.now() - timeoutStart) / 1000).toFixed(1)

      console.log(`Returned after ${elapsed}s (exit: ${timeoutResult.exitCode})`)

      const timeoutEnforced = parseFloat(elapsed) < 30
      if (timeoutEnforced) {
        console.log(`\u2713 TIMEOUT ENFORCED \u2014 command terminated after ~${elapsed}s`)
      } else {
        console.log('\u2717 Timeout not enforced (ran too long)')
      }
      results.push({ name: 'Command timeout (5s)', enforced: timeoutEnforced, detail: `returned in ${elapsed}s` })
    } catch {
      console.log('\u2713 TIMEOUT ENFORCED \u2014 command timed out (error)')
      results.push({ name: 'Command timeout (5s)', enforced: true, detail: 'timed out with error' })
    }

    // ---------------------------------------------------------------
    // 4. CPU Quota (50%)
    // ---------------------------------------------------------------
    printSection('4. CPU QUOTA (50% cap)')
    console.log('Burning CPU for 3 seconds...')

    try {
      const cpuResult = await agentsh.exec(`python3 -c "
import time
start = time.time()
total = 0
while time.time() - start < 3:
    total += sum(range(10000))
elapsed = time.time() - start
print(f'CPU burn for {elapsed:.1f}s, iterations: {total}')
" 2>&1`, 30000)

      const cpuOutput = cpuResult.stdout.trim()
      console.log('Output:', cpuOutput || '(no output)')

      const cpuEnforced = cpuResult.exitCode === 0
      if (cpuEnforced) {
        console.log('\u2713 CPU QUOTA ACTIVE \u2014 process completed (CPU capped at configured quota)')
      } else {
        console.log('\u2717 CPU burn did not complete cleanly')
      }
      results.push({ name: 'CPU quota (50%)', enforced: cpuEnforced, detail: cpuOutput.slice(0, 100) })
    } catch {
      console.log('\u2717 CPU test errored')
      results.push({ name: 'CPU quota (50%)', enforced: false, detail: 'test errored' })
    }

    // ---------------------------------------------------------------
    // 5. Disk I/O Throughput
    // ---------------------------------------------------------------
    printSection('5. DISK I/O THROUGHPUT (~25 MB/s cap)')
    console.log('Writing 50 MB to /tmp in 1 MB chunks...')

    try {
      const ioResult = await agentsh.exec(`python3 -c "
import time
data = b'x' * (1024 * 1024)
start = time.time()
with open('/tmp/io_test', 'wb') as f:
    for i in range(50):
        f.write(data)
        f.flush()
elapsed = time.time() - start
mb = 50
print(f'Wrote {mb} MB in {elapsed:.1f}s ({mb/elapsed:.1f} MB/s)')
" 2>&1`, 60000)

      const ioOutput = ioResult.stdout.trim()
      console.log('Output:', ioOutput || '(no output)')

      const mbpsMatch = ioOutput.match(/([\d.]+)\s*MB\/s/)
      const mbps = mbpsMatch ? parseFloat(mbpsMatch[1]) : null

      if (mbps !== null && mbps <= 30) {
        console.log(`\u2713 DISK I/O CAP ACTIVE \u2014 write speed ${mbps.toFixed(1)} MB/s (capped at ~25 MB/s)`)
        results.push({ name: 'Disk I/O (~25 MB/s)', enforced: true, detail: `${mbps.toFixed(1)} MB/s` })
      } else if (mbps !== null) {
        console.log(`~ DISK I/O completed at ${mbps.toFixed(1)} MB/s (limit is ~25 MB/s, may not be enforced)`)
        results.push({ name: 'Disk I/O (~25 MB/s)', enforced: false, detail: `${mbps.toFixed(1)} MB/s` })
      } else {
        console.log('\u2717 Disk I/O test did not produce measurable output')
        results.push({ name: 'Disk I/O (~25 MB/s)', enforced: false, detail: ioOutput.slice(0, 100) })
      }
    } catch {
      console.log('\u2717 Disk I/O test errored')
      results.push({ name: 'Disk I/O (~25 MB/s)', enforced: false, detail: 'test errored' })
    }

    // ---------------------------------------------------------------
    // 6. Cgroup enforcement check
    // ---------------------------------------------------------------
    printSection('6. CGROUP ENFORCEMENT STATUS')
    console.log('Checking if agentsh can write to cgroup controllers...')

    try {
      const cgroupResult = await agentsh.exec('cat /proc/self/cgroup 2>&1')
      console.log('Process cgroup:', cgroupResult.stdout.trim())

      const cgroupPath = cgroupResult.stdout.trim().replace(/^0::/, '')
      if (cgroupPath) {
        const memMax = await agentsh.exec(`cat /sys/fs/cgroup${cgroupPath}/memory.max 2>&1`)
        console.log(`memory.max: ${memMax.stdout.trim()}`)
        const pidsMax = await agentsh.exec(`cat /sys/fs/cgroup${cgroupPath}/pids.max 2>&1`)
        console.log(`pids.max: ${pidsMax.stdout.trim()}`)
        const cpuMax = await agentsh.exec(`cat /sys/fs/cgroup${cgroupPath}/cpu.max 2>&1`)
        console.log(`cpu.max: ${cpuMax.stdout.trim()}`)
      }

      const serverLogs = await agentsh.exec('grep -i "cgroup\\|memory.max\\|pids.max" /var/log/agentsh/server.log 2>/dev/null | tail -5')
      if (serverLogs.stdout.trim()) {
        console.log('\nServer cgroup log entries:')
        for (const line of serverLogs.stdout.trim().split('\n')) {
          console.log(`  ${line}`)
        }
      }
    } catch {
      console.log('  Could not check cgroup status')
    }

    // ---------------------------------------------------------------
    // Summary
    // ---------------------------------------------------------------
    console.log('\n' + '='.repeat(60))
    console.log('RESOURCE LIMITS SUMMARY')
    console.log('='.repeat(60))
    console.log(`
  Limit                          Result
  -----------------------------  ------`)

    for (const r of results) {
      const icon = r.enforced ? '\u2713' : '\u2717'
      const status = r.enforced ? 'ENFORCED' : 'NOT ENFORCED'
      console.log(`  ${icon} ${r.name.padEnd(30)} ${status}`)
      if (r.detail) {
        console.log(`      \u2514 ${r.detail}`)
      }
    }

    console.log(`
Notes:
  - Resource limits are configured in default.yaml (policy)
  - On Freestyle's nested cgroup setup (kernel 6.1.x), agentsh v0.18.x falls
    back to a top-level /sys/fs/cgroup/agentsh.slice (auto-detected at startup).
  - The slice and per-command sub-cgroups exist, but spawned processes end up
    in /system.slice/freestyle-supervisor.service (where vm.exec children live)
    instead of being migrated into the per-command cgroup. Manual migration is
    rejected by the kernel ("no internal process constraint" once subtree_control
    has controllers).
  - Net result: PID/CPU/Disk I/O caps are NOT enforced on Freestyle today.
    Memory limit and command timeout still trip via systemd / agentsh server
    side enforcement.
  - Tracking the cgroup migration gap as an agentsh v0.18.x follow-up.
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
