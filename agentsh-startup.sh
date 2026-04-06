#!/bin/bash
# Restrict /dev/fuse to prevent any FUSE mount during snapshot
sudo /bin/chmod 600 /dev/fuse 2>/dev/null || true

# Start agentsh server (deferred FUSE: mounts on first exec, not at startup)
agentsh server >> /var/log/agentsh/server.log 2>&1 &

# Wait for server to be ready (health check loop)
for i in $(seq 1 15); do
  if curl -sf http://127.0.0.1:18080/health >/dev/null 2>&1; then break; fi
  sleep 1
done

# Install shell shim (replaces /bin/bash with agentsh shim)
sudo agentsh shim install-shell --root / --shim /usr/bin/agentsh-shell-shim --bash --i-understand-this-modifies-the-host

# Warm up the shim (/dev/fuse restricted, so deferred mount is a no-op)
/bin/bash -c "echo shim warmup ok" 2>/dev/null || true

echo "agentsh ready"
