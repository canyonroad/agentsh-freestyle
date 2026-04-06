import 'dotenv/config'
import { freestyle, Vm, VmSpec } from 'freestyle-sandboxes'
import { VmAgentsh, VmAgentshInstance, ExecResult } from './vm-agentsh.js'

export { ExecResult }

export interface DemoVm {
  vm: Vm & { agentsh: VmAgentshInstance }
  agentsh: VmAgentshInstance
}

export async function createAgentshVm(): Promise<DemoVm> {
  const spec = new VmSpec().with('agentsh', new VmAgentsh())
  const { vm } = await freestyle.vms.create(spec)
  return { vm, agentsh: vm.agentsh }
}

export function printSection(title: string): void {
  console.log('\n' + '='.repeat(60))
  console.log(title)
  console.log('='.repeat(60))
}

export function printResult(description: string, passed: boolean, details?: string): void {
  const icon = passed ? '\u2713' : '\u2717'
  const suffix = details ? `  (${details})` : ''
  console.log(`  ${icon} ${description}${suffix}`)
}

export function printSummary(passed: number, failed: number): void {
  console.log('\n' + '='.repeat(60))
  console.log(`RESULTS: ${passed} passed, ${failed} failed out of ${passed + failed}`)
  console.log('='.repeat(60))
}

export function truncate(str: string, maxLen = 150): string {
  if (str.length <= maxLen) return str
  return str.slice(0, maxLen) + '...'
}
