#!/bin/bash

# Cleanup and restart packet visualizer safely
# This script ensures no stale processes or XDP attachments exist

set -e

echo "🧹 Cleaning up stale processes..."

# Kill all packet-viz processes
sudo pkill -9 -f "packet-viz" 2>/dev/null || true

# Wait for kernel to auto-detach XDP
echo "⏳ Waiting for kernel cleanup..."
sleep 2

# Manually detach XDP if still attached (try both methods)
echo "🔌 Detaching XDP programs..."
sudo ip link set dev wlo1 xdp off 2>/dev/null || true
sudo ip link set dev eth0 xdp off 2>/dev/null || true

# Wait a bit more
sleep 1

# Verify no XDP is attached
XDP_CHECK=$(sudo ip link show wlo1 2>/dev/null | grep -c "xdp" || true)
if [ "$XDP_CHECK" -gt 0 ]; then
    echo "⚠️  Warning: XDP still appears to be attached, but attempting to start anyway..."
fi

echo "✅ Cleanup complete. Starting packet visualizer..."
echo "---"

# Start the application
cd "$(dirname "$0")"
sudo ./bin/packet-viz
