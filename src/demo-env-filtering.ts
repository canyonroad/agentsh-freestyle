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
    console.log('DEMONSTRATING AGENTSH ENVIRONMENT VARIABLE FILTERING')
    console.log('='.repeat(60))

    // Section 1: Discover session environment
    printSection('1. SESSION ENVIRONMENT DISCOVERY')
    console.log('Dumping what the session environment looks like:\n')

    const envDump = await agentsh.exec('env 2>&1 | sort | head -30')
    if (envDump.exitCode === 0 && envDump.stdout.trim()) {
      for (const line of envDump.stdout.trim().split('\n')) {
        console.log(`  ${line}`)
      }
      const total = await agentsh.exec('env 2>&1 | wc -l')
      console.log(`  ... (${total.stdout.trim()} total variables)`)
    } else if (envDump.blocked) {
      console.log('  \u2713 env command blocked by policy')
    } else {
      console.log(`  exit: ${envDump.exitCode}, stderr: ${envDump.stderr.slice(0, 100)}`)
    }

    // Section 2: Check standard variables via bash expansion
    printSection('2. STANDARD VARIABLES (via bash expansion)')
    console.log('Checking if safe variables are accessible:\n')

    const stdVars = [
      { name: 'HOME', cmd: 'echo $HOME' },
      { name: 'PATH', cmd: 'echo $PATH' },
      { name: 'USER', cmd: 'echo $USER' },
      { name: 'SHELL', cmd: 'echo $SHELL' },
      { name: 'PWD', cmd: 'echo $PWD' },
      { name: 'BASH_ENV', cmd: 'echo $BASH_ENV' },
      { name: 'AGENTSH_SERVER', cmd: 'echo $AGENTSH_SERVER' },
      { name: 'HTTPS_PROXY', cmd: 'echo $HTTPS_PROXY' },
    ]

    for (const { name, cmd } of stdVars) {
      const r = await agentsh.exec(cmd)
      const value = r.stdout.trim()
      if (value) {
        console.log(`  \u2713 ${name} = ${value}`)
      } else {
        console.log(`  - ${name} = (not set)`)
      }
    }

    // Section 3: Check printenv for specific vars
    printSection('3. PRINTENV CHECK')
    console.log('Testing printenv for specific variables:\n')

    const printenvVars = ['HOME', 'PATH', 'USER', 'SHELL', 'BASH_ENV', 'AGENTSH_SERVER']
    for (const name of printenvVars) {
      const r = await agentsh.exec(`printenv ${name} 2>&1`)
      const value = r.stdout.trim()
      if (r.blocked) {
        console.log(`  \u2717 ${name}: printenv blocked`)
      } else if (value) {
        console.log(`  \u2713 ${name} = ${value}`)
      } else {
        console.log(`  - ${name} = (not in process environment)`)
      }
    }

    // Section 4: Sensitive vars NOT leaked
    printSection('4. SENSITIVE VARIABLES (should NOT be present)')
    console.log('Credential/secret patterns should be filtered:\n')

    const sensitiveChecks = [
      { desc: 'AWS_SECRET_ACCESS_KEY', cmd: 'echo ${AWS_SECRET_ACCESS_KEY:-not_found}' },
      { desc: 'AWS_ACCESS_KEY_ID', cmd: 'echo ${AWS_ACCESS_KEY_ID:-not_found}' },
      { desc: 'OPENAI_API_KEY', cmd: 'echo ${OPENAI_API_KEY:-not_found}' },
      { desc: 'DATABASE_URL', cmd: 'echo ${DATABASE_URL:-not_found}' },
      { desc: 'SECRET_KEY', cmd: 'echo ${SECRET_KEY:-not_found}' },
      { desc: 'FREESTYLE_API_KEY', cmd: 'echo ${FREESTYLE_API_KEY:-not_found}' },
    ]

    for (const { desc, cmd } of sensitiveChecks) {
      const r = await agentsh.exec(cmd)
      const value = r.stdout.trim()
      if (value === 'not_found' || value === '') {
        console.log(`  \u2713 FILTERED: ${desc}`)
      } else {
        console.log(`  \u2717 LEAKED: ${desc} = ${value.slice(0, 20)}...`)
      }
    }

    // Section 5: Env enumeration via grep
    printSection('5. SENSITIVE PATTERN SCAN')
    console.log('Searching env output for sensitive patterns:\n')

    const envAll = await agentsh.exec('env 2>&1')
    if (envAll.blocked) {
      console.log('  \u2713 env command blocked \u2014 enumeration prevented')
    } else {
      const output = envAll.stdout.toLowerCase()
      const patterns = [
        { pattern: 'aws_', label: 'AWS credentials' },
        { pattern: 'openai', label: 'OpenAI keys' },
        { pattern: '_secret', label: 'Secret values' },
        { pattern: '_token', label: 'Auth tokens' },
        { pattern: '_password', label: 'Passwords' },
        { pattern: 'api_key', label: 'API keys' },
      ]

      for (const { pattern, label } of patterns) {
        if (output.includes(pattern)) {
          console.log(`  \u2717 LEAKED: ${label} (found "${pattern}" in env output)`)
        } else {
          console.log(`  \u2713 FILTERED: ${label} (no "${pattern}" in env output)`)
        }
      }
    }

    // Section 6: Env shim check
    printSection('6. ENVIRONMENT SHIM STATUS')
    const shimPath = '/usr/lib/agentsh/libenvshim.so'
    const shimExists = await agentsh.exec(`test -f ${shimPath} && echo exists || echo missing`)
    console.log(`  libenvshim.so: ${shimExists.stdout.trim()}`)

    const ldPreload = await agentsh.exec('echo $LD_PRELOAD')
    console.log(`  LD_PRELOAD: ${ldPreload.stdout.trim() || '(not set)'}`)

    // Summary
    console.log('\n' + '='.repeat(60))
    console.log('SUMMARY')
    console.log('='.repeat(60))
    console.log(`
Environment variable filtering:

STANDARD VARIABLES:
  Variables on the allowlist (HOME, PATH, etc.) are passed
  through to the session. Bash may also set some internally.

SENSITIVE VARIABLES:
  Credential patterns (AWS_*, OPENAI_API_KEY, *_SECRET, etc.)
  are filtered from the session environment. They are not
  available to commands run through the session API.

ENUMERATION:
  env/printenv output is checked for sensitive patterns.
  If the env shim (libenvshim.so) is loaded via LD_PRELOAD,
  it intercepts getenv/environ calls at the library level.

Policy (default.yaml env section):
  allow: PATH, HOME, NODE_ENV, GIT_*, PYTHONPATH, etc.
  deny:  AWS_*, OPENAI_API_KEY, DATABASE_URL, SECRET_*, etc.
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
