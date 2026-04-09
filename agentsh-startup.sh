#!/bin/bash
# Restrict /dev/fuse to prevent any FUSE mount during snapshot
sudo /bin/chmod 600 /dev/fuse 2>/dev/null || true

# -----------------------------------------------------------------------------
# Prepare the cgroup v2 directory that agentsh will use as base_path
# (config.yaml sets sandbox.cgroups.base_path: /sys/fs/cgroup/agentsh).
#
# Why at the root and not inside our own service slice?
# The freestyle-supervisor.service cgroup has an empty `cgroup.subtree_control`,
# so any sub-cgroup we create inside it has no controller files, which means
# resource limits silently no-op. Creating our dir at the root of cgroupfs —
# where memory/pids/cpu/io are already delegated — gives agentsh a working
# tree to place per-command cgroups in. (Upstream bug: canyonroad/agentsh#197.)
# -----------------------------------------------------------------------------
if [ -d /sys/fs/cgroup ] && [ -w /sys/fs/cgroup ]; then
  mkdir -p /sys/fs/cgroup/agentsh 2>/dev/null || true
  if [ -w /sys/fs/cgroup/agentsh/cgroup.subtree_control ]; then
    # Enable the controllers agentsh needs in children we create below
    echo '+memory +pids +cpu +io' > /sys/fs/cgroup/agentsh/cgroup.subtree_control 2>/dev/null || true
  fi
  echo "cgroup base_path prepared: /sys/fs/cgroup/agentsh"
  ls -la /sys/fs/cgroup/agentsh 2>/dev/null | head -20
  echo "subtree_control: $(cat /sys/fs/cgroup/agentsh/cgroup.subtree_control 2>/dev/null)"
else
  echo "warning: /sys/fs/cgroup not writable, agentsh cgroup base_path may fail"
fi

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
