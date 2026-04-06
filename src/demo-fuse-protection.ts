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

    async function run(desc: string, cmd: string): Promise<void> {
      const r = await agentsh.exec(cmd)
      if (r.blocked || r.exitCode !== 0) {
        console.log(`  \u2717 BLOCKED: ${desc}`)
      } else {
        console.log(`  \u2713 ALLOWED: ${desc}`)
      }
    }

    console.log('='.repeat(60))
    console.log('DEMONSTRATING FUSE/VFS FILE PROTECTION')
    console.log('='.repeat(60))

    // ---------------------------------------------------------------
    // 1. CLI tools to protected dirs (blocked)
    // ---------------------------------------------------------------
    printSection('1. CLI TOOLS TO PROTECTED DIRS (blocked)')
    console.log('Standard CLI commands that attempt writes to protected paths:')
    await run('cp to /etc', 'cp /etc/hostname /etc/hostname.bak 2>&1')
    await run('touch in /etc', 'touch /etc/newfile 2>&1')
    await run('tee to /usr/bin', 'echo hack | tee /usr/bin/evil 2>&1')
    await run('mkdir in /etc', 'mkdir /etc/newdir 2>&1')
    await run('dd write to /etc', 'dd if=/dev/zero of=/etc/ddtest bs=1 count=1 2>&1')

    // ---------------------------------------------------------------
    // 2. Symlink escape attempts (blocked)
    // ---------------------------------------------------------------
    printSection('2. SYMLINK ESCAPE ATTEMPTS (blocked)')
    console.log('Symlinks pointing into protected paths:')
    await run('symlink read /etc/shadow', 'ln -sf /etc/shadow /tmp/shadow_link && cat /tmp/shadow_link 2>&1')
    await run('symlink write /etc/passwd', 'ln -sf /etc/passwd /tmp/passwd_link && echo pwned >> /tmp/passwd_link 2>&1')

    // ---------------------------------------------------------------
    // 3. Python file I/O (blocked) — bypasses shell, tests VFS layer
    // ---------------------------------------------------------------
    printSection('3. PYTHON FILE I/O — VFS LAYER (blocked)')
    console.log('Python open() calls bypass shell policy and hit FUSE directly:')
    await run('python read /etc/shadow', "python3 -c \"print(open('/etc/shadow').read())\" 2>&1")
    await run('python write /etc/fuse_test', "python3 -c \"open('/etc/fuse_test','w').write('hack')\" 2>&1")
    await run('python write /usr/bin/evil', "python3 -c \"open('/usr/bin/evil','w').write('hack')\" 2>&1")
    await run('python listdir /root', "python3 -c \"import os; os.listdir('/root')\" 2>&1")
    await run('python write /var/escape.txt', "python3 -c \"open('/var/escape.txt','w').write('hack')\" 2>&1")

    // ---------------------------------------------------------------
    // 4. Allowed file operations (workspace + /tmp)
    // ---------------------------------------------------------------
    printSection('4. ALLOWED FILE OPERATIONS (workspace + /tmp)')
    console.log('Writes to permitted locations succeed as expected:')
    await run('cp to /tmp', 'cp /etc/hostname /tmp/hostname_copy 2>&1')
    await run('touch in /tmp', 'touch /tmp/newfile 2>&1')
    await run('python write /home/user/test.txt', "python3 -c \"open('/home/user/test.txt','w').write('allowed')\" 2>&1")
    await run('python write /tmp/test.txt', "python3 -c \"open('/tmp/test.txt','w').write('allowed')\" 2>&1")
    await run('cat /home/user/test.txt', 'cat /home/user/test.txt')

    // ---------------------------------------------------------------
    // Summary
    // ---------------------------------------------------------------
    console.log('\n' + '='.repeat(60))
    console.log('FUSE/VFS PROTECTION SUMMARY')
    console.log('='.repeat(60))
    console.log(`
agentsh enforces file protection through 5 security layers:

  1. POLICY BLOCKING (shell layer)
     Commands like cp, touch, tee, mkdir, dd are intercepted
     before they can even attempt a write to a protected path.

  2. FUSE VFS LAYER
     A FUSE filesystem sits between userspace and the kernel.
     All file operations — regardless of which process issues
     them — pass through FUSE before reaching the real disk.
     This catches writes that bypass shell-level policy.

  3. PYTHON / LANGUAGE RUNTIME PROTECTION
     Python's open() calls go directly to the kernel syscall
     without invoking any shell. FUSE intercepts these at the
     VFS level, so write attempts to /etc, /usr, /var, /root
     are denied even when no shell command is involved.

  4. SYMLINK RESOLUTION BLOCKING
     Symlinks that resolve to a protected path are refused at
     the VFS layer. Creating a link in /tmp pointing to /etc
     does not grant write access to /etc.

  5. WORKSPACE ISOLATION
     Only /home/user/** and /tmp/** are writable. All other
     paths are read-only or fully restricted. This confines
     agent activity to an explicit, auditable workspace.

  BLOCKED:  /etc, /usr, /var, /root, /proc, /sys
  ALLOWED:  /home/user/** (workspace), /tmp/**
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
