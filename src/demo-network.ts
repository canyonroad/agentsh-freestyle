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

    async function runCurl(description: string, command: string): Promise<void> {
      console.log(`\n--- ${description} ---`)
      const r = await agentsh.exec(command)
      const code = r.stdout.trim()
      if (r.blocked) {
        console.log(`\u2717 BLOCKED by policy (exit: 126)`)
      } else if (code === '200' || code === '301' || code === '302') {
        console.log(`\u2713 ALLOWED (HTTP ${code})`)
      } else if (code === '403' || code === '400') {
        console.log(`\u2717 BLOCKED by proxy (HTTP ${code})`)
      } else if (code === '000') {
        console.log(`\u2717 CONNECTION REFUSED/BLOCKED (HTTP ${code})`)
      } else if (r.exitCode !== 0) {
        console.log(`\u2717 DENIED (exit: ${r.exitCode}, output: ${code.slice(0, 80)})`)
      } else {
        console.log(`? RESULT: HTTP ${code}, exit: ${r.exitCode}`)
      }
    }

    async function runCmd(description: string, command: string): Promise<void> {
      console.log(`\n--- ${description} ---`)
      const r = await agentsh.exec(command)
      const output = r.stdout.trim()
      if (r.blocked) {
        console.log(`\u2717 BLOCKED by policy`)
      } else if (r.exitCode === 0) {
        console.log(`\u2713 ALLOWED (${output.slice(0, 60)})`)
      } else {
        console.log(`\u2717 DENIED (exit: ${r.exitCode}, output: ${output.slice(0, 80)})`)
      }
    }

    console.log('='.repeat(60))
    console.log('DEMONSTRATING AGENTSH NETWORK POLICY')
    console.log('='.repeat(60))

    // 1. Localhost (allowed)
    printSection('1. LOCALHOST (allowed)')
    await runCurl('curl health endpoint', 'curl -s --connect-timeout 5 -o /dev/null -w "%{http_code}" http://127.0.0.1:18080/health')
    await runCurl('curl localhost:18080/health', 'curl -s --connect-timeout 5 -o /dev/null -w "%{http_code}" http://localhost:18080/health')

    // 2. Cloud Metadata (blocked)
    printSection('2. CLOUD METADATA (blocked)')
    await runCurl('AWS metadata (169.254.169.254)', 'curl -s --connect-timeout 3 -o /dev/null -w "%{http_code}" http://169.254.169.254/latest/meta-data/')
    await runCurl('GCP metadata (metadata.google.internal)', 'curl -s --connect-timeout 3 -o /dev/null -w "%{http_code}" http://metadata.google.internal/')
    await runCurl('Alibaba metadata (100.100.100.200)', 'curl -s --connect-timeout 3 -o /dev/null -w "%{http_code}" http://100.100.100.200/')

    // 3. Private Networks (blocked)
    printSection('3. PRIVATE NETWORKS (blocked)')
    await runCurl('10.0.0.1 (RFC1918)', 'curl -s --connect-timeout 3 -o /dev/null -w "%{http_code}" http://10.0.0.1/')
    await runCurl('172.16.0.1 (RFC1918)', 'curl -s --connect-timeout 3 -o /dev/null -w "%{http_code}" http://172.16.0.1/')
    await runCurl('192.168.1.1 (RFC1918)', 'curl -s --connect-timeout 3 -o /dev/null -w "%{http_code}" http://192.168.1.1/')

    // 4. Package Registries (allowed)
    printSection('4. PACKAGE REGISTRIES (allowed)')
    await runCurl('npm registry', 'curl -s --connect-timeout 10 --max-time 15 -o /dev/null -w "%{http_code}" https://registry.npmjs.org/')
    await runCurl('PyPI', 'curl -s --connect-timeout 10 --max-time 15 -o /dev/null -w "%{http_code}" https://pypi.org/')
    await runCurl('crates.io', 'curl -s --connect-timeout 10 --max-time 15 -o /dev/null -w "%{http_code}" https://crates.io/api/v1/crates?per_page=1')

    // 5. Unknown/Malicious Domains (blocked/denied)
    printSection('5. UNKNOWN/MALICIOUS DOMAINS (blocked)')
    await runCurl('evil.com', 'curl -s --connect-timeout 5 -o /dev/null -w "%{http_code}" https://evil.com/')
    await runCurl('example.com', 'curl -s --connect-timeout 5 -o /dev/null -w "%{http_code}" https://example.com/')
    await runCurl('httpbin.org', 'curl -s --connect-timeout 5 -o /dev/null -w "%{http_code}" https://httpbin.org/get')

    // Summary
    console.log('\n' + '='.repeat(60))
    console.log('SUMMARY')
    console.log('='.repeat(60))
    console.log(`
Network policy enforcement:

ALLOWED:
  \u2713 Localhost (127.0.0.1)     \u2192 allow-localhost
  \u2713 Package registries        \u2192 allow-package-registries
    (npmjs.org, pypi.org, crates.io)

BLOCKED:
  \u2717 Cloud metadata endpoints  \u2192 block-cloud-metadata
    (169.254.169.254, metadata.google.internal)
  \u2717 Private networks          \u2192 block-private-networks
    (10.x, 172.16.x, 192.168.x)
  \u2717 Unknown/malicious domains \u2192 default-deny or block-malicious
    (evil.com, example.com, httpbin.org)
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
