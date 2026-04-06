import 'dotenv/config'
import { freestyle, VmSpec } from 'freestyle-sandboxes'
import { VmAgentsh } from './vm-agentsh.js'
import { printSection } from './helpers.js'

const KNOWN_CAPABILITIES = [
  'seccomp',
  'seccomp_basic',
  'seccomp_user_notify',
  'ebpf',
  'fuse',
  'landlock',
  'cgroups_v2',
  'pid_namespace',
  'user_namespace',
]

function parseCapabilities(output: string): Map<string, boolean> {
  const capabilities = new Map<string, boolean>()
  const lines = output.split('\n')
  let inCapabilities = false

  for (const line of lines) {
    if (/CAPABILITIES/i.test(line)) {
      inCapabilities = true
      continue
    }
    if (inCapabilities) {
      // Lines like "  seccomp_basic  ✓" or "  landlock  ✗"
      const match = line.match(/^\s+(\w+)\s+(✓|✗|[✔✘x])/)
      if (match) {
        const name = match[1]
        const available = match[2] === '✓' || match[2] === '✔'
        capabilities.set(name, available)
      }
    }
  }

  return capabilities
}

async function main() {
  console.log('Creating Freestyle VM with agentsh...')
  const spec = new VmSpec().with('agentsh', new VmAgentsh())
  const { vm } = await freestyle.vms.create(spec)
  const agentsh = vm.agentsh

  try {
    await agentsh.waitReady()

    console.log('='.repeat(60))
    console.log('DEMONSTRATING AGENTSH SECURITY CAPABILITY DETECTION')
    console.log('='.repeat(60))

    // 1. Run agentsh detect
    printSection('1. RAW DETECT OUTPUT')
    const detectResult = await agentsh.exec('agentsh detect 2>&1')
    console.log(detectResult.stdout)
    if (detectResult.stderr) {
      console.log('[stderr]', detectResult.stderr)
    }

    // 2. Parse and display capability matrix
    printSection('2. CAPABILITY MATRIX')
    const detected = parseCapabilities(detectResult.stdout)

    // Merge detected results with known capabilities list
    const allNames = new Set([...KNOWN_CAPABILITIES, ...detected.keys()])
    let available = 0
    let unavailable = 0

    for (const name of allNames) {
      if (detected.has(name)) {
        const present = detected.get(name)!
        const icon = present ? '\u2713' : '\u2717'
        const status = present ? 'available' : 'unavailable'
        console.log(`  ${icon}  ${name.padEnd(24)} ${status}`)
        if (present) available++; else unavailable++
      } else {
        console.log(`  ?  ${name.padEnd(24)} not reported`)
      }
    }

    console.log(`\n  Total: ${available} available, ${unavailable} unavailable`)

    // 3. Additional system info
    printSection('3. AGENTSH VERSION')
    const versionResult = await agentsh.exec('agentsh --version')
    console.log(versionResult.stdout.trim() || versionResult.stderr.trim())

    printSection('4. KERNEL VERSION')
    const unameResult = await agentsh.exec('uname -r')
    console.log('  uname -r:', unameResult.stdout.trim())

    const procVersionResult = await agentsh.exec('cat /proc/version')
    console.log('  /proc/version:', procVersionResult.stdout.trim())

    printSection('5. FUSE AVAILABILITY')
    const fuseResult = await agentsh.exec('ls -la /dev/fuse 2>&1')
    console.log(fuseResult.stdout.trim() || fuseResult.stderr.trim())

    printSection('6. CGROUPS')
    const cgroupResult = await agentsh.exec('mount | grep cgroup')
    if (cgroupResult.stdout.trim()) {
      console.log(cgroupResult.stdout.trim())
    } else {
      console.log('  (no cgroup mounts found)')
    }

    // Summary
    console.log('\n' + '='.repeat(60))
    console.log('SUMMARY')
    console.log('='.repeat(60))
    console.log(`
Kernel security features detected by agentsh:

AVAILABLE (${available}):
${[...allNames]
  .filter(n => detected.get(n) === true)
  .map(n => `  \u2713 ${n}`)
  .join('\n') || '  (none)'}

UNAVAILABLE (${unavailable}):
${[...allNames]
  .filter(n => detected.get(n) === false)
  .map(n => `  \u2717 ${n}`)
  .join('\n') || '  (none)'}
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
