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

    // Section 1: Allowed variables — verify safe vars are present
    printSection('1. ALLOWED VARIABLES (should be present)')
    console.log('(Safe environment variables visible in the VM)\n')

    const allowedVars: Array<{ desc: string; cmd: string }> = [
      { desc: 'HOME', cmd: 'printenv HOME' },
      { desc: 'PATH', cmd: 'printenv PATH' },
      { desc: 'USER', cmd: 'printenv USER' },
      { desc: 'SHELL', cmd: 'printenv SHELL' },
      { desc: 'BASH_ENV (bash startup path)', cmd: 'echo $BASH_ENV' },
      { desc: 'AGENTSH_SERVER (should be http://127.0.0.1:18080)', cmd: 'echo $AGENTSH_SERVER' },
    ]

    for (const { desc, cmd } of allowedVars) {
      const r = await agentsh.exec(cmd)
      const value = r.stdout.trim()
      if (r.blocked) {
        console.log(`  \u2717 NOT FOUND: ${desc} (blocked)`)
      } else if (value) {
        console.log(`  \u2713 PRESENT: ${desc} = ${value}`)
      } else {
        console.log(`  \u2717 NOT FOUND: ${desc} (empty)`)
      }
    }

    // Section 2: Sensitive vars NOT leaked
    printSection('2. SENSITIVE VARIABLES (should NOT be present)')
    console.log('(Credential/secret patterns should be filtered out)\n')

    const sensitivePatterns: Array<{ desc: string; cmd: string }> = [
      { desc: 'AWS_* credentials', cmd: 'env | grep -i AWS_ || echo "not found"' },
      { desc: 'OPENAI API keys', cmd: 'env | grep -i OPENAI || echo "not found"' },
      { desc: '_SECRET variables', cmd: 'env | grep -i _SECRET || echo "not found"' },
      { desc: '_TOKEN variables', cmd: 'env | grep -i _TOKEN || echo "not found"' },
      { desc: '_PASSWORD variables', cmd: 'env | grep -i _PASSWORD || echo "not found"' },
      { desc: 'FREESTYLE_API_KEY', cmd: 'env | grep -i FREESTYLE_API_KEY || echo "not found"' },
    ]

    for (const { desc, cmd } of sensitivePatterns) {
      const r = await agentsh.exec(cmd)
      const output = r.stdout.trim()
      if (r.blocked) {
        console.log(`  \u2713 FILTERED: ${desc} (command blocked)`)
      } else if (output === 'not found' || output === '') {
        console.log(`  \u2713 FILTERED: ${desc}`)
      } else {
        console.log(`  \u2717 LEAKED: ${desc} = ${output.slice(0, 80)}`)
      }
    }

    // Section 3: Env enumeration protection
    printSection('3. ENV ENUMERATION PROTECTION')
    console.log('(Bulk env listing commands should be blocked or filtered)\n')

    const enumCmds: Array<{ desc: string; cmd: string }> = [
      { desc: '`env` command', cmd: 'env 2>&1' },
      { desc: '`printenv` command', cmd: 'printenv 2>&1' },
      { desc: '`set | head -20` (shell builtins)', cmd: 'set 2>&1 | head -20' },
    ]

    for (const { desc, cmd } of enumCmds) {
      const r = await agentsh.exec(cmd)
      const output = r.stdout.trim()

      if (r.blocked) {
        console.log(`  \u2713 FILTERED: ${desc} — blocked by policy (exit: 126)`)
      } else if (r.exitCode !== 0 && !output) {
        console.log(`  \u2713 FILTERED: ${desc} — denied (exit: ${r.exitCode})`)
      } else {
        // Check if any sensitive values leaked in the output
        const lowerOutput = output.toLowerCase()
        const leakedPatterns = ['aws_', 'openai', '_secret', '_token', '_password', 'freestyle_api_key']
        const leaked = leakedPatterns.filter(p => lowerOutput.includes(p))
        if (leaked.length > 0) {
          console.log(`  \u2717 LEAKED: ${desc} — sensitive vars visible: ${leaked.join(', ')}`)
          console.log(`    Output (first 200 chars): ${output.slice(0, 200)}`)
        } else {
          const lineCount = output ? output.split('\n').length : 0
          console.log(`  \u2713 FILTERED: ${desc} — ${lineCount} lines, no sensitive vars found`)
          if (output) {
            console.log(`    Sample (first 100 chars): ${output.slice(0, 100)}`)
          }
        }
      }
    }

    // Summary
    console.log('\n' + '='.repeat(60))
    console.log('SUMMARY')
    console.log('='.repeat(60))
    console.log(`
Environment variable filtering in action:

ALLOWED (safe vars passed through):
  \u2713 HOME, PATH, USER, SHELL  \u2192 Standard POSIX vars
  \u2713 BASH_ENV                 \u2192 agentsh shim activation
  \u2713 AGENTSH_SERVER           \u2192 Server endpoint for shim

FILTERED (credential patterns blocked):
  \u2713 AWS_*                    \u2192 Cloud credentials
  \u2713 OPENAI*                  \u2192 AI API keys
  \u2713 *_SECRET                 \u2192 Secret values
  \u2713 *_TOKEN                  \u2192 Auth tokens
  \u2713 *_PASSWORD               \u2192 Passwords
  \u2713 FREESTYLE_API_KEY        \u2192 Platform API key

ENUMERATION PROTECTION:
  \u2713 env / printenv            \u2192 Blocked or filtered output
  \u2713 set                       \u2192 Checked for leakage
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
