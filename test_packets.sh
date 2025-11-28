#!/bin/bash

# Start the packet visualizer in the background
echo "Starting Packet Visualizer..."
sudo ./bin/packet-viz > /tmp/packet-viz.log 2>&1 &
SERVER_PID=$!

# Wait for server to start
sleep 3

# Generate some traffic
echo "Generating network traffic..."
for i in {1..10}; do
    ping -c 1 8.8.8.8 > /dev/null 2>&1 &
    sleep 0.5
done

# Wait for packets to be processed
sleep 3

# Check the stats
echo ""
echo "=== API Stats ==="
curl -s http://localhost:5000/api/stats | python3 -m json.tool 2>/dev/null || echo "Failed to get stats"

echo ""
echo "=== First 5 Flows ==="
curl -s http://localhost:5000/api/flows | python3 -m json.tool 2>/dev/null | head -50 || echo "Failed to get flows"

# Stop the server
echo ""
echo "Stopping server..."
kill $SERVER_PID 2>/dev/null
wait $SERVER_PID 2>/dev/null

echo "Done!"
