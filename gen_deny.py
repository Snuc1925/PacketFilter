import random

def generate_ips(n=100):
    ips = set()
    while len(ips) < n:
        x = random.randint(0, 254)
        if x == 100:  # bỏ qua x = 100
            continue
        y = random.randint(0, 254)
        ip = f"192.168.{x}.{y}"
        ips.add(ip)
    return ips

if __name__ == "__main__":
    ips = generate_ips()
    with open("blacklist.conf", "w") as f:
        for ip in ips:
            f.write(f"deny {ip};\n")
    print("✅ Đã tạo file blacklist.conf với 100 IP.")
