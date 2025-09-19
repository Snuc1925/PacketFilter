#!/bin/bash

# Check if running as root (needed for sudo commands)
if [ "$EUID" -ne 0 ]; then
  echo "Please run as root or with sudo"
  exit 1
fi

# Install required packages
# echo "Installing required packages..."
# apt-get update
# apt-get install -y nginx python3-pip tcpdump

# Create venv
python3 -m venv venv
source venv/bin/activate

# Install Python dependencies inside venv
pip install psutil matplotlib pandas plotly

# Check for victim-ns namespace
if ! ip netns list | grep -q victim-ns; then
  echo "Creating victim-ns namespace..."
  ip netns add victim-ns
  
  # Configure the namespace with network access
  # This is a minimal setup - adjust as needed
  ip link add veth0 type veth peer name veth1
  ip link set veth1 netns victim-ns
  ip addr add 192.168.100.1/24 dev veth0
  ip netns exec victim-ns ip addr add 192.168.100.2/24 dev veth1
  ip link set veth0 up
  ip netns exec victim-ns ip link set veth1 up
  ip netns exec victim-ns ip link set lo up
  
  # Setup default route in the namespace
  ip netns exec victim-ns ip route add default via 192.168.100.1
fi

# Run the monitoring script
echo "Starting monitoring script..."
python3 nginx_monitor.py "$@"

echo "Done!"