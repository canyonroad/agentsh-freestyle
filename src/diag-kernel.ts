/**
 * Independent kernel capability probe — does NOT use agentsh detect.
 *
 * Goal: verify the Freestyle team's claim that BPF and cgroups-v2 are
 * "enabled" by asking the kernel directly on a bare VM. This bypasses
 * agentsh entirely so we can distinguish between:
 *
 *   (a) the kernel not having the feature
 *   (b) agentsh dropping the capability at startup
 *   (c) agentsh's `detect` mis-reporting what's there
 */
import 'dotenv/config'
import { readFileSync } from 'fs'
import { resolve } from 'path'
import { freestyle, VmSpec } from 'freestyle-sandboxes'

const DIAG_SCRIPT = readFileSync(resolve('src/diag-kernel.sh'), 'utf-8')

async function uploadAndRun(vm: any): Promise<void> {
  // upload the script via additionalFiles-style cat heredoc (single round-trip)
  const writeCmd = `cat > /tmp/diag.sh <<'DIAGEOF_SENTINEL'\n${DIAG_SCRIPT}\nDIAGEOF_SENTINEL\nchmod +x /tmp/diag.sh`
  await vm.exec({ command: writeCmd, timeoutMs: 15000 })
  const r = await vm.exec({ command: 'bash /tmp/diag.sh 2>&1', timeoutMs: 180000 })
  console.log(r.stdout ?? '')
  if (r.stderr) console.log('[stderr]\n' + r.stderr)
  console.log('[diag exit=' + (r.exitCode ?? '?') + ']')
}

async function runDiagOnBareVm(): Promise<void> {
  console.log('\n' + '#'.repeat(72))
  console.log('# BARE FREESTYLE VM (no agentsh, raw root shell)')
  console.log('#'.repeat(72))
  console.log('Creating bare VM with bpftool, gcc, libcap2-bin pre-installed...')

  const spec = new VmSpec()
    .aptDeps('bpftool', 'gcc', 'libc6-dev', 'linux-libc-dev', 'libcap2-bin')

  const { vm } = await freestyle.vms.create(spec)
  try {
    await uploadAndRun(vm)
  } finally {
    console.log('\nStopping bare VM...')
    try { await vm.stop() } catch {}
  }
}

async function runDiagOnAgentshVm(): Promise<void> {
  const { VmAgentsh } = await import('./vm-agentsh.js')
  console.log('\n' + '#'.repeat(72))
  console.log('# AGENTSH-PROVISIONED VM (raw vm.exec, not via agentsh API)')
  console.log('#'.repeat(72))
  console.log('Creating VM with agentsh spec + bpftool/gcc/libcap2-bin...')

  const spec = new VmSpec()
    .with('agentsh', new VmAgentsh())
    .aptDeps('bpftool', 'gcc', 'libc6-dev', 'linux-libc-dev', 'libcap2-bin')
  const { vm } = await freestyle.vms.create(spec as any)
  try {
    const agentsh = (vm as any).agentsh
    try { await agentsh.waitReady() } catch (e) {
      console.log('(agentsh not ready yet, continuing anyway: ' + (e instanceof Error ? e.message : e) + ')')
    }
    await uploadAndRun(vm)

    // Also: ask agentsh what IT thinks is available, on the exact same VM.
    // This is the side-by-side comparison — raw kernel facts above, agentsh
    // detect output below.
    console.log('\n' + '#'.repeat(72))
    console.log('# AGENTSH DETECT OUTPUT (from the same VM)')
    console.log('#'.repeat(72))
    try {
      const detect = await agentsh.exec('agentsh detect 2>&1', 30000)
      console.log(detect.stdout?.trim() || '(empty stdout)')
      if (detect.stderr?.trim()) console.log('[stderr] ' + detect.stderr.trim())
      console.log('[exit=' + detect.exitCode + ']')
    } catch (e) {
      console.log('agentsh detect failed: ' + (e instanceof Error ? e.message : e))
    }

    // Bonus: look at the agentsh server's actual capability set, since that's
    // the process that would be using bpf(). If the server dropped caps on
    // startup, this tells us exactly what it has left.
    console.log('\n# agentsh server process capabilities')
    try {
      const srv = await vm.exec({
        command: `PID=$(pgrep -f 'agentsh (server|start)' | head -1); ` +
                 `echo "server pid=$PID"; ` +
                 `if [ -n "$PID" ]; then ` +
                 `  grep -E '^Cap(Inh|Prm|Eff|Bnd|Amb)' /proc/$PID/status; ` +
                 `  CAPEFF=$(awk '/^CapEff:/{print $2}' /proc/$PID/status); ` +
                 `  echo "server CapEff=$CAPEFF"; ` +
                 `  capsh --decode=$CAPEFF 2>&1; ` +
                 `fi`,
        timeoutMs: 10000
      })
      console.log(srv.stdout ?? '')
      if (srv.stderr) console.log('[stderr] ' + srv.stderr)
    } catch (e) {
      console.log('server cap probe failed: ' + (e instanceof Error ? e.message : e))
    }
  } finally {
    console.log('\nStopping agentsh VM...')
    try { await vm.stop() } catch {}
  }
}

async function main() {
  const mode = process.argv[2] ?? 'both'
  if (mode === 'bare' || mode === 'both') {
    await runDiagOnBareVm()
  }
  if (mode === 'agentsh' || mode === 'both') {
    await runDiagOnAgentshVm()
  }
  console.log('\nDone.')
}

main().catch(err => { console.error(err); process.exit(1) })
