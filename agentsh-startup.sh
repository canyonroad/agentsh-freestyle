#!/bin/bash
# Restrict /dev/fuse to prevent any FUSE mount during snapshot
sudo /bin/chmod 600 /dev/fuse 2>/dev/null || true

# Cgroups v2: v0.18.0 (canyonroad/agentsh#202 / #214) auto-detects the freestyle
# nested-cgroup limitation (#197 — empty subtree_control under
# freestyle-supervisor.service) and falls back to a top-level
# /sys/fs/cgroup/agentsh.slice. The slice is created and per-command
# sub-cgroups appear, BUT processes spawned by the agentsh server end up
# under /system.slice/freestyle-supervisor.service (the cgroup that owns
# vm.exec children) rather than the per-command cgroup, so resource limits
# (pids_max / memory.max) are NOT enforced. Manual cgroup re-parenting from
# the startup script is rejected by the kernel ("no internal process
# constraint" once subtree_control has controllers). Tracking as a follow-up
# upstream — for now, the PID-limit test is documented as a gap.

# Start agentsh server in background (deferred FUSE: mounts on first exec)
agentsh server >> /var/log/agentsh/server.log 2>&1 &
SERVER_PID=$!

# Wait for server to be ready (health check loop)
for i in $(seq 1 15); do
  if curl -sf http://127.0.0.1:18080/health >/dev/null 2>&1; then break; fi
  sleep 1
done

# Install shell shim (replaces /bin/bash with agentsh shim)
sudo agentsh shim install-shell --root / --shim /usr/bin/agentsh-shell-shim --bash --i-understand-this-modifies-the-host

# Warm up the shim
/bin/bash -c "echo shim warmup ok" 2>/dev/null || true

echo "agentsh ready"

# Keep the script alive so systemd doesn't kill the service cgroup
wait $SERVER_PID
