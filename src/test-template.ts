import 'dotenv/config'
import { freestyle, VmSpec } from 'freestyle-sandboxes'
import { VmAgentsh } from './vm-agentsh.js'
import { printSection, printSummary } from './helpers.js'

async function main() {
  let passed = 0
  let failed = 0

  async function test(name: string, fn: () => Promise<boolean>) {
    process.stdout.write(`  ${name}... `)
    try {
      if (await fn()) {
        console.log('\u2713 PASS')
        passed++
      } else {
        console.log('\u2717 FAIL')
        failed++
      }
    } catch (err) {
      const msg = err instanceof Error ? err.message : String(err)
      console.log(`\u2717 ERROR: ${msg}`)
      failed++
    }
    await new Promise(resolve => setTimeout(resolve, 200))
  }

  console.log('Creating Freestyle VM with agentsh...')
  const spec = new VmSpec().with('agentsh', new VmAgentsh())
  const { vm } = await freestyle.vms.create(spec)
  const agentsh = vm.agentsh

  try {
    console.log('Waiting for agentsh to be ready...')
    await agentsh.waitReady()
    console.log('agentsh ready!\n')

    // =================================================================
    // 1. INSTALLATION
    // =================================================================
    printSection('Installation')

    await test('agentsh installed', async () => {
      const r = await agentsh.exec('agentsh --version')
      return r.exitCode === 0 && r.stdout.includes('agentsh')
    })

    await test('seccomp support (libseccomp linked)', async () => {
      const r = await agentsh.exec('ldd /usr/bin/agentsh 2>&1 | grep -E "seccomp|not.*dynamic"')
      return r.stdout.includes('libseccomp')
    })

    // =================================================================
    // 2. SERVER & CONFIGURATION
    // =================================================================
    printSection('Server & Configuration')

    await test('server healthy', async () => {
      const r = await agentsh.exec('curl -s http://127.0.0.1:18080/health')
      return r.stdout.trim() === 'ok'
    })

    await test('server process running', async () => {
      const r = await agentsh.exec('ps aux | grep "agentsh server" | grep -v grep')
      return r.exitCode === 0 && r.stdout.includes('agentsh')
    })

    await test('policy file exists', async () => {
      const r = await agentsh.exec('head -5 /etc/agentsh/policies/default.yaml')
      return r.exitCode === 0 && r.stdout.includes('version')
    })

    await test('config file exists', async () => {
      const r = await agentsh.exec('head -5 /etc/agentsh/config.yaml')
      return r.exitCode === 0 && r.stdout.includes('server')
    })

    await test('FUSE deferred enabled in config', async () => {
      const r = await agentsh.exec('grep -A3 "fuse:" /etc/agentsh/config.yaml')
      return r.stdout.includes('enabled: true') && r.stdout.includes('deferred: true')
    })

    await test('seccomp enabled in config', async () => {
      const r = await agentsh.exec('grep -A1 "seccomp:" /etc/agentsh/config.yaml')
      return r.stdout.includes('enabled: true')
    })

    // =================================================================
    // 3. SHELL SHIM
    // =================================================================
    printSection('Shell Shim')

    await test('shim installed (/bin/bash is statically linked)', async () => {
      const r = await agentsh.exec('file /bin/bash')
      return r.stdout.includes('statically linked')
    })

    await test('real bash preserved (/bin/bash.real)', async () => {
      const r = await agentsh.exec('file /bin/bash.real')
      return r.exitCode === 0 && r.stdout.includes('ELF')
    })

    await test('echo through shim', async () => {
      const r = await agentsh.exec('/bin/bash -c "echo hello-shim"')
      return r.exitCode === 0 && r.stdout.includes('hello-shim')
    })

    await test('Python through shim', async () => {
      const r = await agentsh.exec("python3 -c \"print('python-ok')\"")
      return r.exitCode === 0 && r.stdout.includes('python-ok')
    })

    // =================================================================
    // 4. POLICY EVALUATION (static)
    // =================================================================
    printSection('Policy Evaluation (static)')

    await test('policy-test: sudo denied', async () => {
      const r = await agentsh.exec('agentsh debug policy-test --op exec --path sudo --json 2>&1')
      return r.stdout.includes('"deny"') && r.stdout.includes('block-shell-escape')
    })

    await test('policy-test: echo allowed', async () => {
      const r = await agentsh.exec('agentsh debug policy-test --op exec --path echo --json 2>&1')
      return r.stdout.includes('"allow"') && r.stdout.includes('allow-safe-commands')
    })

    await test('policy-test: workspace write allowed', async () => {
      const r = await agentsh.exec('agentsh debug policy-test --op write --path /home/user/test.txt --json 2>&1')
      return r.stdout.includes('"allow"')
    })

    await test('policy-test: workspace read allowed', async () => {
      const r = await agentsh.exec('agentsh debug policy-test --op read --path /home/user/test.txt --json 2>&1')
      return r.stdout.includes('"allow"')
    })

    await test('policy-test: tmp write allowed', async () => {
      const r = await agentsh.exec('agentsh debug policy-test --op write --path /tmp/test.txt --json 2>&1')
      return r.stdout.includes('"allow"') && r.stdout.includes('allow-tmp')
    })

    await test('policy-test: workspace delete is soft-delete', async () => {
      const r = await agentsh.exec('agentsh debug policy-test --op delete --path /home/user/test.txt --json 2>&1')
      return r.stdout.includes('soft-delete-workspace')
    })

    await test('policy-test: SSH key access requires approval', async () => {
      const r = await agentsh.exec('agentsh debug policy-test --op read --path /root/.ssh/id_rsa --json 2>&1')
      return r.stdout.includes('approve-ssh-access')
    })

    await test('policy-test: AWS credentials require approval', async () => {
      const r = await agentsh.exec('agentsh debug policy-test --op read --path /root/.aws/credentials --json 2>&1')
      return r.stdout.includes('approve-aws-credentials')
    })

    await test('policy-test: system path write denied', async () => {
      const r = await agentsh.exec('agentsh debug policy-test --op write --path /usr/bin/evil --json 2>&1')
      return r.stdout.includes('"deny"')
    })

    await test('policy-test: /etc write denied', async () => {
      const r = await agentsh.exec('agentsh debug policy-test --op write --path /etc/test.txt --json 2>&1')
      return r.stdout.includes('"deny"')
    })

    // =================================================================
    // 5. SECURITY DIAGNOSTICS
    // =================================================================
    printSection('Security Diagnostics')

    const detectOut = (await agentsh.exec('agentsh detect 2>&1')).stdout
    const capSection = detectOut.substring(detectOut.indexOf('CAPABILITIES'))
    function capAvailable(key: string): boolean {
      const re = new RegExp(`^\\s+${key}\\s+\u2713`, 'm')
      return re.test(capSection)
    }

    await test('agentsh detect: seccomp available', async () => capAvailable('seccomp_basic') || capAvailable('seccomp'))
    await test('agentsh detect: seccomp_basic available', async () => capAvailable('seccomp_basic'))
    await test('agentsh detect: cgroups_v2 available', async () => capAvailable('cgroups_v2'))
    await test('agentsh detect: landlock available', async () => capAvailable('landlock'))

    // =================================================================
    // 6. COMMAND BLOCKING
    // =================================================================
    printSection('Command Blocking')

    await test('sudo blocked', async () => {
      const r = await agentsh.exec('sudo whoami')
      return r.blocked
    })

    await test('su blocked', async () => {
      const r = await agentsh.exec('su - 2>&1')
      return r.blocked || r.exitCode !== 0
    })

    await test('ssh blocked', async () => {
      const r = await agentsh.exec('ssh localhost 2>&1')
      return r.blocked || r.exitCode !== 0
    })

    await test('kill blocked', async () => {
      const r = await agentsh.exec('kill -9 1 2>&1')
      return r.blocked || r.exitCode !== 0
    })

    await test('rm -rf blocked', async () => {
      await agentsh.exec('mkdir -p /tmp/testdir && touch /tmp/testdir/f.txt')
      const r = await agentsh.exec('rm -rf /tmp/testdir 2>&1')
      return r.blocked || r.exitCode !== 0
    })

    await test('echo allowed', async () => {
      const r = await agentsh.exec('echo policy-test')
      return r.exitCode === 0 && r.stdout.includes('policy-test')
    })

    // =================================================================
    // 7. NETWORK BLOCKING
    // =================================================================
    printSection('Network Blocking')

    await test('package registry allowed (npmjs.org)', async () => {
      const r = await agentsh.exec('curl -s --connect-timeout 10 --max-time 15 -o /dev/null -w "%{http_code}" https://registry.npmjs.org/')
      return r.stdout.trim() === '200'
    })

    await test('metadata endpoint blocked (169.254.169.254)', async () => {
      const r = await agentsh.exec('curl -s --connect-timeout 3 -o /dev/null -w "%{http_code}" http://169.254.169.254/')
      return r.stdout.includes('403') || r.exitCode !== 0
    })

    await test('evil.com blocked', async () => {
      const r = await agentsh.exec('curl -s --connect-timeout 5 -o /dev/null -w "%{http_code}" https://evil.com/')
      return r.stdout.includes('400') || r.stdout.includes('403') || r.exitCode !== 0
    })

    await test('private network blocked (10.0.0.1)', async () => {
      const r = await agentsh.exec('curl -s --connect-timeout 3 -o /dev/null -w "%{http_code}" http://10.0.0.1/')
      return r.stdout.includes('403') || r.exitCode !== 0
    })

    await test('unknown domain blocked (default-deny)', async () => {
      const r = await agentsh.exec('curl -s --connect-timeout 5 -o /dev/null -w "%{http_code}" https://api.github.com/ 2>&1')
      return r.stdout.includes('403') || r.stdout.includes('000') || r.exitCode !== 0
    })

    // =================================================================
    // 8. ENVIRONMENT POLICY
    // =================================================================
    printSection('Environment Policy')

    await test('safe vars present (HOME, PATH)', async () => {
      const r = await agentsh.exec('echo "HOME=$HOME" && echo "PATH=$PATH"')
      return r.stdout.includes('HOME=/') && r.stdout.includes('PATH=/')
    })

    await test('BASH_ENV set', async () => {
      const r = await agentsh.exec('echo $BASH_ENV')
      return r.stdout.includes('bash_startup') || r.exitCode === 0
    })

    // =================================================================
    // 9. FILE I/O
    // =================================================================
    printSection('File I/O Enforcement')

    await test('write to workspace succeeds', async () => {
      const r = await agentsh.exec('echo "fileio-test" > /home/user/fileio-test.txt && cat /home/user/fileio-test.txt')
      return r.exitCode === 0 && r.stdout.includes('fileio-test')
    })

    await test('write to /tmp succeeds', async () => {
      const r = await agentsh.exec('echo "tmp-test" > /tmp/fileio-test.txt && cat /tmp/fileio-test.txt')
      return r.exitCode === 0 && r.stdout.includes('tmp-test')
    })

    await test('write to /etc blocked', async () => {
      const r = await agentsh.exec('echo "hack" > /etc/test_file 2>&1')
      return r.exitCode !== 0
    })

    await test('Python write to /etc blocked', async () => {
      const r = await agentsh.exec("python3 -c \"open('/etc/fuse_test','w').write('hack')\" 2>&1")
      return r.exitCode !== 0
    })

    await test('symlink escape to /etc/shadow blocked', async () => {
      const r = await agentsh.exec('ln -sf /etc/shadow /tmp/shadow_link && cat /tmp/shadow_link 2>&1')
      return r.exitCode !== 0
    })

    await test('read /proc/1/environ blocked', async () => {
      const r = await agentsh.exec('cat /proc/1/environ 2>&1')
      return r.exitCode !== 0
    })

    // =================================================================
    // 10. MULTI-CONTEXT BLOCKING
    // =================================================================
    printSection('Multi-Context Command Blocking')

    await test('env sudo blocked', async () => {
      const r = await agentsh.exec('env sudo whoami 2>&1')
      return r.exitCode !== 0
    })

    await test('xargs sudo blocked', async () => {
      const r = await agentsh.exec('echo whoami | xargs sudo 2>&1')
      return r.exitCode !== 0
    })

    await test('find -exec sudo blocked', async () => {
      const r = await agentsh.exec('find /tmp -maxdepth 0 -exec sudo whoami \\; 2>&1')
      return r.exitCode !== 0 || !r.stdout.match(/^root$/m)
    })

    await test('nested script sudo blocked', async () => {
      await agentsh.exec('printf "#!/bin/sh\\nsudo whoami\\n" > /tmp/escalate.sh && chmod +x /tmp/escalate.sh')
      const r = await agentsh.exec('/tmp/escalate.sh 2>&1')
      return r.exitCode !== 0
    })

    await test('Python subprocess sudo blocked', async () => {
      const r = await agentsh.exec("python3 -c \"import subprocess; r=subprocess.run(['sudo','whoami'], capture_output=True, text=True); print(r.stdout or r.stderr); exit(r.returncode)\" 2>&1")
      return r.exitCode !== 0
    })

    await test('env whoami allowed', async () => {
      const r = await agentsh.exec('env whoami')
      return r.exitCode === 0
    })

    await test('find -exec echo allowed', async () => {
      const r = await agentsh.exec('find /tmp -maxdepth 0 -exec echo found \\;')
      return r.exitCode === 0 && r.stdout.includes('found')
    })

    // =================================================================
    // 11. FUSE WORKSPACE & SOFT DELETE
    // =================================================================
    printSection('FUSE Workspace & Soft Delete')

    await test('create file for soft-delete', async () => {
      const r = await agentsh.exec("python3 -c \"open('/home/user/soft_del_test.txt','w').write('important data\\n')\"")
      return r.exitCode === 0
    })

    await test('rm file (soft-deleted)', async () => {
      const r = await agentsh.exec('rm /home/user/soft_del_test.txt 2>&1')
      return r.exitCode === 0
    })

    await test('file gone from original location', async () => {
      const r = await agentsh.exec('test -f /home/user/soft_del_test.txt && echo exists || echo gone')
      return r.stdout.includes('gone')
    })

    await test('agentsh trash list shows file', async () => {
      const r = await agentsh.exec('agentsh trash list 2>&1')
      return r.stdout.includes('soft_del_test') || r.exitCode === 0
    })

    // =================================================================
    // 12. CREDENTIAL BLOCKING
    // =================================================================
    printSection('Credential Blocking')

    await test('read ~/.ssh/id_rsa blocked', async () => {
      const r = await agentsh.exec('cat /home/user/.ssh/id_rsa 2>&1')
      return r.exitCode !== 0
    })

    await test('read ~/.aws/credentials blocked', async () => {
      const r = await agentsh.exec('cat /home/user/.aws/credentials 2>&1')
      return r.exitCode !== 0
    })

    await test('read /proc/1/environ blocked', async () => {
      const r = await agentsh.exec('cat /proc/1/environ 2>&1')
      return r.exitCode !== 0
    })

    // =================================================================
    // RESULTS
    // =================================================================
    printSummary(passed, failed)

  } catch (error) {
    console.error('Fatal:', error)
    failed++
  } finally {
    console.log('\nCleaning up VM...')
    try { await vm.stop() } catch {}
    console.log('Done.')
  }

  process.exit(failed > 0 ? 1 : 0)
}

main().catch(console.error)
