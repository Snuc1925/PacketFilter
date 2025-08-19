sudo ip netns add attacker-ns
ip netns list
sudo ip link add veth-srv type veth peer name veth-att

# Đưa một đầu veth vào namespace
sudo ip link set veth-att netns attacker-ns
# Gán IP 192.168.100.1 cho veth-srv
sudo ip addr add 192.168.100.1/24 dev veth-srv

# Bật giao diện veth-srv
sudo ip link set veth-srv up

# Gán IP 192.168.100.2 cho veth-att
sudo ip netns exec attacker-ns ip addr add 192.168.100.2/24 dev veth-att

# Bật giao diện veth-att
sudo ip netns exec attacker-ns ip link set veth-att up

# Bật giao diện loopback bên trong namespace (quan trọng cho nhiều công cụ)
sudo ip netns exec attacker-ns ip link set lo up
