import pandas as pd
import matplotlib.pyplot as plt

# Load dữ liệu
cpu_df = pd.DataFrame({
    "connection": [5, 10, 50, 100, 300, 500, 1000],
    "ebpf_cpu_usage": [0.1, 0.2, 0.2, 0.3, 0.3, 0.3, 0.4],
    "nginx_cpu_usage": [40, 80, 95, 99, 100, 100, 100]
})

latency_df = pd.DataFrame({
    "connection": [5, 10, 50, 100, 300, 500, 1000],
    "ebpf_latency": [0.34, 0.37, 0.40, 0.25, 0.30, 0.35, 0.37],
    "nginx_latency": [0.45, 0.8, 3.8, 7, 21, 40, 55]
})

# Vẽ chart CPU usage
plt.figure(figsize=(8,5))
plt.plot(cpu_df["connection"], cpu_df["ebpf_cpu_usage"], marker="o", label="eBPF CPU Usage")
plt.plot(cpu_df["connection"], cpu_df["nginx_cpu_usage"], marker="o", label="Nginx CPU Usage")
plt.xlabel("Connections")
plt.ylabel("CPU Usage (%)")
plt.title("CPU Usage Comparison")
plt.legend()
plt.grid(True)
plt.show()

# Vẽ chart Latency
plt.figure(figsize=(8,5))
plt.plot(latency_df["connection"], latency_df["ebpf_latency"], marker="o", label="eBPF Latency")
plt.plot(latency_df["connection"], latency_df["nginx_latency"], marker="o", label="Nginx Latency")
plt.xlabel("Connections")
plt.ylabel("Latency (ms)")
plt.title("Latency Comparison")
plt.legend()
plt.grid(True)
plt.show()