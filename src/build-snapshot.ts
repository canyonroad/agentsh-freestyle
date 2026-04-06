import 'dotenv/config'
import { freestyle, VmSpec } from 'freestyle-sandboxes'
import { VmAgentsh } from './vm-agentsh.js'

async function main() {
  console.log('Creating Freestyle VM with agentsh for snapshot...')

  const spec = new VmSpec().with('agentsh', new VmAgentsh())
  const { vm } = await freestyle.vms.create(spec)

  try {
    console.log('Waiting for agentsh to be ready...')
    await vm.agentsh.waitReady()
    console.log('agentsh ready!')

    // Verify installation
    const version = await vm.agentsh.exec('agentsh --version')
    console.log(`agentsh version: ${version.stdout.trim()}`)

    const health = await vm.agentsh.exec('curl -s http://127.0.0.1:18080/health')
    console.log(`Server health: ${health.stdout.trim()}`)

    const shim = await vm.agentsh.exec('file /bin/bash')
    console.log(`Shell shim: ${shim.stdout.trim()}`)

    // Create snapshot
    console.log('\nCreating snapshot...')
    const { snapshotId } = await vm.snapshot()
    console.log(`\nSnapshot created successfully!`)
    console.log(`Snapshot ID: ${snapshotId}`)
    console.log(`\nTo use this snapshot, create VMs with:`)
    console.log(`  freestyle.vms.create({ snapshotId: '${snapshotId}' })`)

  } catch (error) {
    console.error('Error:', error)
    process.exit(1)
  }
}

main().catch(console.error)
