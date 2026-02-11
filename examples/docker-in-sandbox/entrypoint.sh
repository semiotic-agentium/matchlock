#!/bin/sh
set -e

# Start containerd
containerd &

# Wait for containerd socket
for i in $(seq 1 30); do
    if [ -S /run/containerd/containerd.sock ]; then
        break
    fi
    sleep 0.5
done

# Start dockerd without iptables/bridge - the VM's network stack
# already provides connectivity, so containers use --network=host.
exec dockerd \
  --containerd /run/containerd/containerd.sock \
  --iptables=false \
  --bridge=none
