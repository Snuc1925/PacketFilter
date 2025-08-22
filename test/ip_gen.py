import random

N = 999  # số lượng IP muốn sinh
ips = ["192.168.100.3"]

for _ in range(N):
    x = 100
    while x == 100:  # đảm bảo x != 100
        x = random.randint(1, 254)
    y = random.randint(1, 254)
    ips.append(f"192.168.{x}.{y}")

print("interface=veth-srv")
print("ip_blacklist=" + ",".join(ips))
