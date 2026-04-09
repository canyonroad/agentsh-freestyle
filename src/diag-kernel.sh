#!/bin/bash
# Kernel capability diagnostic — runs as raw root shell on a Freestyle VM.
# Probes BPF and cgroups-v2 directly (bypassing agentsh) to verify what
# the kernel actually supports.
set +e

section() { echo; echo "==========================================="; echo "=== $1"; echo "==========================================="; }

section "01. identity / uname"
id
uname -a
cat /proc/version

section "02. capabilities (current shell)"
grep -E '^Cap(Inh|Prm|Eff|Bnd|Amb)' /proc/self/status
echo "--- capsh --print ---"
capsh --print 2>&1 || echo "(capsh not available)"
echo "--- capsh --decode on CapEff ---"
CAPEFF=$(awk '/^CapEff:/{print $2}' /proc/self/status)
echo "CapEff=$CAPEFF"
capsh --decode="$CAPEFF" 2>&1 || echo "(capsh decode failed)"

section "03. LSMs active in this kernel"
cat /sys/kernel/security/lsm 2>&1 || echo "(securityfs not mounted)"

section "04. relevant sysctls"
for f in \
  /proc/sys/kernel/unprivileged_bpf_disabled \
  /proc/sys/net/core/bpf_jit_enable \
  /proc/sys/kernel/bpf_stats_enabled \
  /proc/sys/kernel/perf_event_paranoid \
  /proc/sys/kernel/kptr_restrict ; do
  printf "%s = " "$f"; cat "$f" 2>&1
done

section "05. BPF filesystem"
echo "--- mountpoint /sys/fs/bpf ---"
mountpoint /sys/fs/bpf 2>&1
echo "--- ls /sys/fs/bpf ---"
ls -la /sys/fs/bpf/ 2>&1 | head -20
echo "--- mount | grep bpf ---"
mount | grep -i bpf 2>&1

section "06. bpftool version + feature probe"
which bpftool
bpftool version 2>&1
echo "--- bpftool feature probe kernel (trimmed) ---"
bpftool feature probe kernel 2>&1 | grep -E '(bpf\(\) syscall|JIT |eBPF JIT|eBPF Hardened|Large program size|program_type |map_type |Scanning|is (available|enabled|restricted))' | head -80
echo "..."
echo "--- bpftool prog show ---"
bpftool prog show 2>&1 | head -20
echo "--- bpftool map show ---"
bpftool map show 2>&1 | head -10

section "07. DIRECT bpf() syscall probe via C (BPF_PROG_LOAD)"
cat > /tmp/bpf_probe.c <<'CEOF'
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <errno.h>
#include <unistd.h>
#include <sys/syscall.h>
#include <linux/bpf.h>

#ifndef __NR_bpf
#define __NR_bpf 321
#endif

int main(void) {
    /* r0 = 0; exit; — minimal valid eBPF program */
    struct bpf_insn insns[] = {
        { .code = 0xb7, .dst_reg = 0, .src_reg = 0, .off = 0, .imm = 0 },
        { .code = 0x95, .dst_reg = 0, .src_reg = 0, .off = 0, .imm = 0 },
    };
    char log[8192] = {0};
    union bpf_attr attr;
    memset(&attr, 0, sizeof(attr));
    attr.prog_type = BPF_PROG_TYPE_SOCKET_FILTER;
    attr.insn_cnt = 2;
    attr.insns    = (unsigned long)insns;
    attr.license  = (unsigned long)"GPL";
    attr.log_buf  = (unsigned long)log;
    attr.log_size = sizeof(log);
    attr.log_level = 1;

    long fd = syscall(__NR_bpf, BPF_PROG_LOAD, &attr, sizeof(attr));
    if (fd < 0) {
        int e = errno;
        printf("BPF_PROG_LOAD FAIL errno=%d (%s)\n", e, strerror(e));
        if (log[0]) printf("verifier log:\n%s\n", log);
        return e;
    }
    printf("BPF_PROG_LOAD OK fd=%ld\n", fd);
    return 0;
}
CEOF
echo "--- compile ---"
gcc -o /tmp/bpf_probe /tmp/bpf_probe.c 2>&1 || echo "(compile failed)"
echo "--- run ---"
/tmp/bpf_probe 2>&1
echo "exit=$?"

section "08. cgroups v2 — mount state"
mount | grep cgroup 2>&1
echo "--- /proc/self/cgroup ---"
cat /proc/self/cgroup
echo "--- ls /sys/fs/cgroup ---"
ls -la /sys/fs/cgroup/ 2>&1 | head -40

section "09. cgroups v2 — controllers"
echo "--- root cgroup.controllers ---"
cat /sys/fs/cgroup/cgroup.controllers 2>&1
echo "--- root cgroup.subtree_control ---"
cat /sys/fs/cgroup/cgroup.subtree_control 2>&1

section "10. cgroups v2 — can we create a sub-cgroup and write limits?"
MYCG=$(awk -F: '/^0::/{print $3}' /proc/self/cgroup)
echo "my cgroup path: $MYCG"
echo "--- my cgroup directory contents ---"
ls -la "/sys/fs/cgroup${MYCG}" 2>&1 | head -30
echo "--- controllers visible in my cgroup ---"
cat "/sys/fs/cgroup${MYCG}/cgroup.controllers" 2>&1
echo "--- subtree_control in my cgroup ---"
cat "/sys/fs/cgroup${MYCG}/cgroup.subtree_control" 2>&1

echo "--- attempt: mkdir /sys/fs/cgroup/diag-test ---"
mkdir /sys/fs/cgroup/diag-test 2>&1
echo "exit=$?"
if [ -d /sys/fs/cgroup/diag-test ]; then
  echo "(created) contents:"
  ls -la /sys/fs/cgroup/diag-test/ 2>&1 | head -30

  echo "--- write memory.max=10MiB ---"
  echo 10485760 > /sys/fs/cgroup/diag-test/memory.max 2>&1
  echo "exit=$?"
  cat /sys/fs/cgroup/diag-test/memory.max 2>&1

  echo "--- write pids.max=50 ---"
  echo 50 > /sys/fs/cgroup/diag-test/pids.max 2>&1
  echo "exit=$?"
  cat /sys/fs/cgroup/diag-test/pids.max 2>&1

  echo "--- write cpu.max=50% ---"
  echo "50000 100000" > /sys/fs/cgroup/diag-test/cpu.max 2>&1
  echo "exit=$?"
  cat /sys/fs/cgroup/diag-test/cpu.max 2>&1

  rmdir /sys/fs/cgroup/diag-test 2>&1
  echo "rmdir exit=$?"
fi

echo "--- attempt: mkdir inside my own cgroup (${MYCG}/diag-sub) ---"
mkdir "/sys/fs/cgroup${MYCG}/diag-sub" 2>&1
echo "exit=$?"
if [ -d "/sys/fs/cgroup${MYCG}/diag-sub" ]; then
  ls -la "/sys/fs/cgroup${MYCG}/diag-sub/" 2>&1 | head -20
  echo "--- write memory.max to sub ---"
  echo 10485760 > "/sys/fs/cgroup${MYCG}/diag-sub/memory.max" 2>&1
  echo "exit=$?"
  cat "/sys/fs/cgroup${MYCG}/diag-sub/memory.max" 2>&1
  rmdir "/sys/fs/cgroup${MYCG}/diag-sub" 2>&1
fi

section "11. Kernel config flags (if readable)"
if [ -r /proc/config.gz ]; then
  zcat /proc/config.gz | grep -E '^CONFIG_(BPF|CGROUP|LANDLOCK|SECURITY_LANDLOCK|BPF_JIT|BPF_SYSCALL|NET_CLS_BPF|BPF_LSM|BPF_EVENTS)=' | sort
elif [ -r "/boot/config-$(uname -r)" ]; then
  grep -E '^CONFIG_(BPF|CGROUP|LANDLOCK|SECURITY_LANDLOCK|BPF_JIT|BPF_SYSCALL|NET_CLS_BPF|BPF_LSM|BPF_EVENTS)=' "/boot/config-$(uname -r)" | sort
else
  echo "(no kernel config readable)"
fi

section "12. landlock sanity"
ls /sys/kernel/security/landlock 2>&1
ls /sys/kernel/security/ 2>&1

echo
echo "=== DIAG COMPLETE ==="
