import os
import re

class CPULogParser:
    def __init__(self):
        self.data = {
            "nginx_cpu": []
        }

    def parse_cpu_logs(self):
        """Parse CPU usage logs"""
        print("Parsing CPU usage logs...")

        if not os.path.exists("cpu_usage.log"):
            print("CPU usage log file not found")
            return

        try:
            with open("cpu_usage.log", "r") as f:
                log_lines = f.readlines()

            cpu_usage = []

            for line in log_lines:
                # Skip header lines and empty lines
                if not line.strip():
                    continue
                if ("AM" in line or "PM" in line) and "nginx" in line:
                    parts = re.split(r'\s+', line.strip())
                    # Example: Timestamp UID PID %usr %system %guest %wait %CPU CPU Command
                    if len(parts) >= 8:
                        try:
                            cpu_percent = float(parts[7])  # %CPU column
                            cpu_usage.append(cpu_percent)
                        except (ValueError, IndexError):
                            continue

            self.data["nginx_cpu"] = cpu_usage
            print("Parsed data:", self.data)

        except Exception as e:
            print(f"Error parsing CPU logs: {e}")


if __name__ == "__main__":
    parser = CPULogParser()
    parser.parse_cpu_logs()
