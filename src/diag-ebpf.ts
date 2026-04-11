/**
 * Focused eBPF / BTF probe — tests whether the BTF-missing claim is correct,
 * and whether agentsh's eBPF gate is too conservative.
 *
 * Question: does Freestyle actually have working eBPF but we have wrong
 * detection? Three things to check independently:
 *
 *   1. Is /sys/kernel/btf/vmlinux actually missing? (or hidden somewhere?)
 *   2. Can a BTF-using bpf() syscall succeed on this kernel?
 *   3. What does agentsh ACTUALLY say when we force ebpf.enabled=true?
 *
 * Until now we've been relying on the claim "kernel ships without BTF" as
 * the reason eBPF is off. Time to verify it directly.
 */
import 'dotenv/config'
import { freestyle, VmSpec } from 'freestyle-sandboxes'
import { VmAgentsh } from './vm-agentsh.js'

const PROBE = `
set +e

section() { echo; echo "===== $1 ====="; }

section "0. kernel"
uname -a
cat /proc/version

section "1. BTF FILE PRESENCE"
echo "--- /sys/kernel/btf/vmlinux ---"
ls -la /sys/kernel/btf/vmlinux 2>&1 || echo "(MISSING /sys/kernel/btf/vmlinux)"
echo "--- /sys/kernel/btf/ directory ---"
ls -la /sys/kernel/btf/ 2>&1 | head -30 || echo "(no /sys/kernel/btf dir)"
echo "--- count of btf objects ---"
ls /sys/kernel/btf/ 2>/dev/null | wc -l
echo "--- vmlinux file size if present ---"
stat -c '%n %s bytes' /sys/kernel/btf/vmlinux 2>/dev/null || echo "(no vmlinux btf file)"
echo "--- alternative BTF locations ---"
find / -name 'vmlinux*' -type f 2>/dev/null | grep -v proc | grep -v sys/module | head -10
find / -name 'btf' -type d 2>/dev/null | head -10

section "2. KERNEL CONFIG (BTF flags)"
if [ -r /proc/config.gz ]; then
  echo "--- /proc/config.gz ---"
  zcat /proc/config.gz | grep -E 'CONFIG_(DEBUG_INFO_BTF|BPF)' | sort
elif [ -r "/boot/config-\$(uname -r)" ]; then
  echo "--- /boot/config-\$(uname -r) ---"
  grep -E 'CONFIG_(DEBUG_INFO_BTF|BPF)' "/boot/config-\$(uname -r)" 2>/dev/null | sort || echo "(no readable config)"
else
  echo "(no kernel config readable — neither /proc/config.gz nor /boot/config-\$(uname -r))"
fi

section "3. bpftool BTF queries"
which bpftool
bpftool version 2>&1 | head -3
echo "--- bpftool btf list ---"
bpftool btf list 2>&1 | head -20
echo "--- bpftool btf dump file /sys/kernel/btf/vmlinux format raw 2>&1 | head -5 ---"
bpftool btf dump file /sys/kernel/btf/vmlinux format raw 2>&1 | head -5
echo "--- bpftool feature probe kernel | grep -i btf ---"
bpftool feature probe kernel 2>&1 | grep -i btf | head -10

section "4. RAW bpf() SYSCALL — minimal socket filter (no BTF needed)"
cat > /tmp/bpf_min.c <<'CEOF'
#include <stdio.h>
#include <string.h>
#include <errno.h>
#include <unistd.h>
#include <sys/syscall.h>
#include <linux/bpf.h>
#ifndef __NR_bpf
#define __NR_bpf 321
#endif
int main(void) {
    /* r0 = 0; exit; — minimal valid eBPF program. dst_reg/src_reg are
       bit-fields; some toolchains zero-initialize them via the designator
       and some don't, so set them explicitly to be safe. */
    struct bpf_insn insns[] = {
        { .code = 0xb7, .dst_reg = 0, .src_reg = 0, .off = 0, .imm = 0 },
        { .code = 0x95, .dst_reg = 0, .src_reg = 0, .off = 0, .imm = 0 },
    };
    char log[4096] = {0};
    union bpf_attr a; memset(&a, 0, sizeof(a));
    a.prog_type = BPF_PROG_TYPE_SOCKET_FILTER;
    a.insn_cnt = 2;
    a.insns    = (unsigned long)insns;
    a.license  = (unsigned long)"GPL";
    a.log_buf  = (unsigned long)log;
    a.log_size = sizeof(log);
    a.log_level = 1;
    long fd = syscall(__NR_bpf, BPF_PROG_LOAD, &a, sizeof(a));
    if (fd < 0) {
        printf("BPF_PROG_LOAD FAIL errno=%d (%s)\\n", errno, strerror(errno));
        if (log[0]) printf("verifier log:\\n%s\\n", log);
        return 1;
    }
    printf("BPF_PROG_LOAD OK fd=%ld (kernel accepts socket-filter eBPF programs)\\n", fd);
    return 0;
}
CEOF
gcc -o /tmp/bpf_min /tmp/bpf_min.c 2>&1 || echo "(compile failed)"
/tmp/bpf_min 2>&1

section "5. RAW bpf() SYSCALL — BPF_BTF_LOAD (BTF actually used by kernel)"
cat > /tmp/btf_load.c <<'CEOF'
#include <stdio.h>
#include <string.h>
#include <errno.h>
#include <unistd.h>
#include <sys/syscall.h>
#include <linux/bpf.h>
#ifndef __NR_bpf
#define __NR_bpf 321
#endif
/* Minimal valid BTF blob: header + zero-length type + zero-length string sections */
int main(void) {
    /* Header: magic=0xeB9F, version=1, flags=0, hdr_len=24,
       type_off=0, type_len=0, str_off=0, str_len=1 */
    unsigned char btf[25] = {
        0x9f,0xeb, 0x01, 0x00,            /* magic, version, flags */
        24,0,0,0,                          /* hdr_len = 24 */
        0,0,0,0,                            /* type_off = 0 */
        0,0,0,0,                            /* type_len = 0 */
        0,0,0,0,                            /* str_off = 0 */
        1,0,0,0,                            /* str_len = 1 */
        0                                    /* string section: just the empty string */
    };
    union bpf_attr a; memset(&a, 0, sizeof(a));
    a.btf = (unsigned long)btf;
    a.btf_size = sizeof(btf);
    long fd = syscall(__NR_bpf, BPF_BTF_LOAD, &a, sizeof(a));
    if (fd < 0) { printf("BPF_BTF_LOAD FAIL errno=%d (%s)\\n", errno, strerror(errno)); return 1; }
    printf("BPF_BTF_LOAD OK fd=%ld\\n", fd);
    return 0;
}
CEOF
gcc -o /tmp/btf_load /tmp/btf_load.c 2>&1 || echo "(compile failed)"
/tmp/btf_load 2>&1

section "6. RAW bpf() SYSCALL — BPF_BTF_GET_NEXT_ID (does kernel know about ANY BTF?)"
cat > /tmp/btf_iter.c <<'CEOF'
#include <stdio.h>
#include <string.h>
#include <errno.h>
#include <unistd.h>
#include <sys/syscall.h>
#include <linux/bpf.h>
#ifndef __NR_bpf
#define __NR_bpf 321
#endif
int main(void) {
    union bpf_attr a; memset(&a, 0, sizeof(a));
    a.start_id = 0;
    long ret = syscall(__NR_bpf, BPF_BTF_GET_NEXT_ID, &a, sizeof(a));
    if (ret < 0) {
        printf("BPF_BTF_GET_NEXT_ID FAIL errno=%d (%s) — no BTF objects in kernel\\n", errno, strerror(errno));
        return 0;
    }
    printf("BPF_BTF_GET_NEXT_ID OK first id=%u\\n", a.next_id);
    int seen = 1;
    while (1) {
        union bpf_attr b; memset(&b, 0, sizeof(b));
        b.start_id = a.next_id;
        long r2 = syscall(__NR_bpf, BPF_BTF_GET_NEXT_ID, &b, sizeof(b));
        if (r2 < 0) break;
        a.next_id = b.next_id;
        seen++;
        if (seen > 100) break;
    }
    printf("total BTF objects iterated: %d\\n", seen);
    return 0;
}
CEOF
gcc -o /tmp/btf_iter /tmp/btf_iter.c 2>&1 || echo "(compile failed)"
/tmp/btf_iter 2>&1
`

const FORCE_EBPF_PROBE = `
set +e
echo
echo "===== 7. agentsh detect (current state) ====="
agentsh detect 2>&1 | tee /tmp/detect.before.txt | head -80

echo
echo "===== 8. Try forcing ebpf.enabled=true and restarting ====="
echo "--- stopping agentsh service ---"
systemctl stop agentsh 2>&1
sleep 1
echo "--- pkill any stragglers ---"
pkill -9 -f 'agentsh server' 2>&1
sleep 1
echo "--- backing up config ---"
cp /etc/agentsh/config.yaml /tmp/config.yaml.bak
echo "--- patching config: ebpf.enabled false -> true ---"
python3 <<'PYEOF'
import re
path = '/etc/agentsh/config.yaml'
with open(path) as f: c = f.read()
# Match the ebpf: block and flip the first 'enabled: false' under it
new = re.sub(
    r'(ebpf:\\s*\\n\\s*enabled:\\s*)false',
    r'\\1true',
    c,
    count=1,
    flags=re.MULTILINE,
)
if new == c:
    print("WARN: no ebpf.enabled:false pattern matched; trying broader regex")
    new = re.sub(r'(ebpf:[^\\n]*\\n[^\\n]*enabled:\\s*)false', r'\\1true', c, count=1)
with open(path, 'w') as f: f.write(new)
print("OK patched")
PYEOF
echo "--- diff (showing the flip) ---"
diff /tmp/config.yaml.bak /etc/agentsh/config.yaml || true

echo "--- starting agentsh server in foreground for 6s, capturing log ---"
timeout 6 agentsh server --config /etc/agentsh/config.yaml > /tmp/agentsh-ebpf.log 2>&1 &
WAITPID=\$!
sleep 5
if kill -0 \$WAITPID 2>/dev/null; then
  echo ">>> SERVER IS RUNNING WITH ebpf.enabled=true <<<"
  kill \$WAITPID 2>/dev/null
  wait \$WAITPID 2>/dev/null
else
  EXIT=\$?
  echo ">>> SERVER EXITED (code=\$EXIT). Server log: <<<"
fi
echo "--- /tmp/agentsh-ebpf.log ---"
cat /tmp/agentsh-ebpf.log

echo
echo "===== 9. agentsh detect with ebpf forced on ====="
agentsh detect 2>&1 | head -80

echo
echo "===== 10. restoring original config ====="
cp /tmp/config.yaml.bak /etc/agentsh/config.yaml
systemctl start agentsh 2>&1 || true
`

async function main() {
  console.log('# eBPF/BTF detection probe on Freestyle VM')
  console.log('# Goal: verify whether the "no BTF" claim is correct, and what')
  console.log('# error agentsh actually produces when ebpf.enabled is forced on.')
  console.log()
  console.log('Creating agentsh-provisioned VM with bpftool/gcc/python3...')

  const spec = new VmSpec()
    .with('agentsh', new VmAgentsh())
    .aptDeps('bpftool', 'gcc', 'libc6-dev', 'linux-libc-dev', 'python3')
  const { vm } = await freestyle.vms.create(spec as any)

  try {
    const agentsh = (vm as any).agentsh
    try { await agentsh.waitReady() } catch (e) {
      console.log('(agentsh waitReady warning: ' + (e instanceof Error ? e.message : e) + ')')
    }

    // Phase A: kernel-level BTF probes via raw vm.exec
    console.log('\n' + '#'.repeat(72))
    console.log('# PHASE A — kernel-level BTF probes (raw vm.exec, bypasses agentsh)')
    console.log('#'.repeat(72))
    const writeProbe = `cat > /tmp/probe.sh <<'SHEOF'\n${PROBE}\nSHEOF\nchmod +x /tmp/probe.sh`
    await vm.exec({ command: writeProbe, timeoutMs: 15000 })
    const r = await vm.exec({ command: 'bash /tmp/probe.sh 2>&1', timeoutMs: 120000 })
    console.log(r.stdout ?? '')
    if (r.stderr) console.log('[stderr]\n' + r.stderr)

    // Phase B: force ebpf and observe
    console.log('\n' + '#'.repeat(72))
    console.log('# PHASE B — force agentsh ebpf.enabled=true, capture error')
    console.log('#'.repeat(72))
    const writeForce = `cat > /tmp/force.sh <<'SHEOF'\n${FORCE_EBPF_PROBE}\nSHEOF\nchmod +x /tmp/force.sh`
    await vm.exec({ command: writeForce, timeoutMs: 15000 })
    const r2 = await vm.exec({ command: 'bash /tmp/force.sh 2>&1', timeoutMs: 60000 })
    console.log(r2.stdout ?? '')
    if (r2.stderr) console.log('[stderr]\n' + r2.stderr)

  } catch (err) {
    console.error('error:', err)
  } finally {
    console.log('\nStopping VM...')
    try { await vm.stop() } catch {}
    console.log('Done.')
  }
}

main().catch(err => { console.error(err); process.exit(1) })
