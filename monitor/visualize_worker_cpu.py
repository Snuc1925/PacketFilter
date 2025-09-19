import pandas as pd
import matplotlib.pyplot as plt

# Đọc file, bỏ qua các dòng bắt đầu bằng "Linux", "Average", hoặc dòng trống
df = pd.read_csv(
    "cpu_usage.log",
    sep=r"\s+",  # thay cho delim_whitespace
    comment="L",  # bỏ dòng bắt đầu bằng "Linux"
    skip_blank_lines=True,
    names=["Time", "AMPM", "UID", "PID", "%usr", "%system", "%guest", "%wait", "%CPU", "CPU", "Command"],
    skiprows=2,   # bỏ thêm dòng "Timestamp UID PID ..."
    engine="python"
)

# Chỉ lấy dòng của nginx
df = df[df["Command"] == "nginx"]

# Ghép Time + AMPM thành datetime, chỉ cần format %I:%M:%S %p
df["Timestamp"] = pd.to_datetime(df["Time"] + " " + df["AMPM"], format="%I:%M:%S %p")

# Chỉ giữ cột cần
df = df[["Timestamp", "%CPU"]]
df["%CPU"] = pd.to_numeric(df["%CPU"], errors="coerce")

# Vẽ biểu đồ
plt.figure(figsize=(10,5))
plt.plot(df["Timestamp"], df["%CPU"], marker="o", linestyle="-", label="nginx %CPU")
plt.xlabel("Time")
plt.ylabel("%CPU")
plt.title("Nginx Worker CPU Usage Over Time")
plt.legend()
plt.grid(True)
plt.show()
