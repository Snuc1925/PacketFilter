import pandas as pd
import matplotlib.pyplot as plt

# dữ liệu
data = {
    "connections": [1, 5, 10, 50, 100, 500, 1000],
    "nginx_kb_s": [380, 352, 285, 92, 50, 10, 7],
    "bpf_kb_s": [390, 382, 385, 380, 363, 337, 313]
}
df = pd.DataFrame(data)

# vẽ chart với connections là category
plt.figure(figsize=(9,5))
plt.plot(df["connections"].astype(str), df["nginx_kb_s"], marker="o", label="Nginx")
plt.plot(df["connections"].astype(str), df["bpf_kb_s"], marker="s", label="BPF")

plt.xlabel("Số lượng connections")
plt.ylabel("Traffic sạch (KB/s)")
plt.title("So sánh khả năng chặn giữa Nginx và BPF")
plt.legend()
plt.grid(True, linestyle="--", alpha=0.6)

# annotate số liệu
for x, y in zip(df["connections"].astype(str), df["nginx_kb_s"]):
    plt.text(x, y+5, f"{y:.0f}", ha="center", fontsize=8, color="blue")
for x, y in zip(df["connections"].astype(str), df["bpf_kb_s"]):
    plt.text(x, y+5, f"{y:.0f}", ha="center", fontsize=8, color="orange")

plt.tight_layout()
plt.savefig("result_clean.png", dpi=300)
plt.show()

