#!/usr/bin/env python3
import subprocess
import time
import os
import signal
import re
import psutil
import matplotlib.pyplot as plt
import threading
from datetime import datetime
import shutil
import argparse

class Benchmark:
    def __init__(self, duration=10):
        base_dir = os.path.dirname(os.path.abspath(__file__))  # thư mục chứa nginx_monitor.py
        jmeter_dir = os.path.join(base_dir, "apache-jmeter-5.6.3")
        self.jmeter_path = os.path.join(jmeter_dir, "bin", "jmeter")
        self.test_jmx_path = os.path.join(jmeter_dir, "test.jmx")
        self.duration = duration
        self.nginx_pid = None
        self.stop_event = threading.Event()
        self.data = {
            'time': [],
            'nginx_cpu': [],
            'nginx_rps': [],
            'nginx_bps': [],
            'client_rps': [],
            'client_bps': [],
            'client_latency': []
        }
        self.cpu_monitor_process = None
        
    def start_nginx(self):
        """Start Nginx with the provided configuration"""
        print("Starting Nginx...")
        subprocess.run(["sudo", "systemctl", "restart", "nginx"], check=True)
        
        # Find Nginx worker process
        for proc in psutil.process_iter(['pid', 'name', 'cmdline']):
            if proc.info['name'] == 'nginx' and 'worker process' in ' '.join(proc.info['cmdline'] or []):
                self.nginx_pid = proc.info['pid']
                break
        
        if not self.nginx_pid:
            raise Exception("Could not find Nginx worker process")
        
        print(f"Nginx worker PID: {self.nginx_pid}")
        
        # Clear Nginx access log
        subprocess.run(["sudo", "truncate", "-s", "0", "/var/log/nginx/access.log"])
        
    def stop_nginx(self):
        """Stop Nginx server"""
        print("Stopping Nginx...")
        # subprocess.run(["sudo", "nginx", "-s", "stop"])
        
    def start_monitor_cpu(self):
        """Monitor Nginx worker CPU usage"""
        print("Starting CPU monitoring...")
        
        # Remove previous CPU log if exists
        if os.path.exists("cpu_usage.log"):
            os.remove("cpu_usage.log")
            
        # Create a command to monitor CPU usage and save to file
        # Using pidstat to monitor the nginx worker process
        cmd = f"pidstat -p $(pgrep -o -P $(pgrep -o nginx)) 1 > cpu_usage.log"
        self.cpu_monitor_process = subprocess.Popen(cmd, shell=True, preexec_fn=os.setsid)
        print(f"CPU monitoring started with PID: {self.cpu_monitor_process.pid}")
            
    def stop_monitor_cpu(self):
        """Stop CPU monitoring process"""
        if self.cpu_monitor_process:
            print("Stopping CPU monitoring...")
            # Kill the entire process group
            os.killpg(os.getpgid(self.cpu_monitor_process.pid), signal.SIGTERM)
            self.cpu_monitor_process.wait()
            print("CPU monitoring stopped")
            
    def run_jmeter_test(self):
        """Run JMeter test from victim-ns namespace"""
        print("Starting JMeter test...")
        
        # Generate results file name with timestamp
        results_file = f"results.jtl"
        
        jmeter_cmd = [
            "sudo", "ip", "netns", "exec", "victim-ns",
            self.jmeter_path, "-n", "-t", self.test_jmx_path,
            "-l", results_file, "-f"   # -f để ghi đè file cũ
        ]
        
        try:
            # Run JMeter without processing output in real-time as it affects performance
            jmeter_proc = subprocess.Popen(
                jmeter_cmd,
                stdout=subprocess.PIPE,
                stderr=subprocess.PIPE,
                text=True
            )
            
            # Wait for JMeter to finish
            jmeter_proc.wait()
            
            # Process results file after test completes
            if os.path.exists(results_file):
                self.process_jmeter_results(results_file)
            else:
                print(f"Warning: JMeter results file {results_file} not found")
                
        except Exception as e:
            print(f"Error running JMeter test: {e}")
    
    def process_jmeter_results(self, results_file):
        """Process JMeter results file (.jtl)"""
        print(f"Processing JMeter results from {results_file}...")
        
        try:
            # Read the JTL file
            with open(results_file, 'r') as f:
                lines = f.readlines()[1:]  # Skip header
            
            if not lines:
                print("No data in JMeter results file")
                return
                
            # Group by second
            timestamps = {}
            bytes_by_second = {}
            latencies_by_second = {}
            
            for line in lines:
                parts = line.split(',')
                if len(parts) >= 15:
                    timestamp_ms = int(parts[0])  # milliseconds since epoch
                    elapsed = int(parts[1])       # response time in ms
                    bytes_received = int(parts[9])
                    latency = int(parts[14])
                    
                    # Convert to seconds
                    second = timestamp_ms // 1000
                    
                    if second not in timestamps:
                        timestamps[second] = 0
                        bytes_by_second[second] = 0
                        latencies_by_second[second] = []
                        
                    timestamps[second] += 1
                    bytes_by_second[second] += bytes_received
                    latencies_by_second[second].append(latency)
            
            # Sort by time
            sorted_seconds = sorted(timestamps.keys())
            start_second = sorted_seconds[0]
            
            # Fill in data arrays
            for second in sorted_seconds:
                relative_second = second - start_second
                
                # Store data
                self.data['time'].append(relative_second)
                self.data['client_rps'].append(timestamps[second])
                self.data['client_bps'].append(bytes_by_second[second])
                self.data['client_latency'].append(
                    sum(latencies_by_second[second]) / len(latencies_by_second[second])
                    if latencies_by_second[second] else 0
                )
                
        except Exception as e:
            print(f"Error processing JMeter results: {e}")
            
    def parse_nginx_logs(self):
        """Parse Nginx access logs to extract RPS, BPS_in, BPS_out per second
           based on the provided log format.
        """
        print("Parsing Nginx access logs...")

        try:
            log_file_path = "/var/log/nginx/access.log"
            if not os.path.exists(log_file_path):
                print(f"Error: Nginx access log file not found at {log_file_path}")
                return

            with open(log_file_path, "r", encoding='utf-8', errors='ignore') as f:
                log_lines = f.readlines()

            if not log_lines:
                print("No data in Nginx access logs.")
                return

            # Biểu thức chính quy KHỚP CHÍNH XÁC VỚI ĐỊNH DẠNG LOG CỦA BẠN
            # ip                     timestamp        request_length       "request"      status   body_bytes_sent "user_agent"
            log_pattern = re.compile(
                r'(\S+) (\d+\.\d+) (\d+) "([^"]+)" (\d+) (\d+) "([^"]*)"'
            )

            # Dictionary để lưu trữ tổng request, bytes_in, bytes_out theo mỗi giây
            requests_per_second = {}
            bytes_in_per_second = {}
            bytes_out_per_second = {}
            
            # Để tính thời gian tương đối cho biểu đồ
            min_timestamp_from_logs = float('inf')

            for line in log_lines:
                match = log_pattern.match(line)
                if match:
                    timestamp_float = float(match.group(2)) # Group 2: Timestamp $msec
                    second_floor = int(timestamp_float)     # Làm tròn xuống để nhóm theo giây

                    request_length = int(match.group(3)) # Group 3: Request Length ($request_length)
                    body_bytes_sent = int(match.group(6)) # Group 6: Body Bytes Sent ($body_bytes_sent)

                    # Cập nhật số liệu cho giây này
                    requests_per_second[second_floor] = requests_per_second.get(second_floor, 0) + 1
                    bytes_in_per_second[second_floor] = bytes_in_per_second.get(second_floor, 0) + request_length
                    bytes_out_per_second[second_floor] = bytes_out_per_second.get(second_floor, 0) + body_bytes_sent
                    
                    # Cập nhật thời điểm sớm nhất để tính thời gian tương đối
                    if timestamp_float < min_timestamp_from_logs:
                        min_timestamp_from_logs = timestamp_float

            print("\n--- Nginx Parsed Data (per second) ---")
            print("Requests per second:", requests_per_second)
            print("Bytes In per second:", bytes_in_per_second)
            print("Bytes Out per second:", bytes_out_per_second)
            print("--------------------------------------\n")

            # Chuyển đổi kết quả từ dictionary sang list trong self.data
            if not requests_per_second:
                print("No requests found in Nginx logs after parsing.")
                return

            # Sắp xếp các giây theo thứ tự thời gian
            sorted_seconds = sorted(requests_per_second.keys())
            
            # Chuẩn bị dữ liệu cho self.data
            # time (relative), nginx_rps, nginx_bps_in, nginx_bps_out
            for second_epoch in sorted_seconds:
                # Tính thời gian tương đối từ thời điểm bắt đầu log
                relative_time = second_epoch - int(min_timestamp_from_logs) # Làm tròn min_timestamp
                
                self.data['time'].append(relative_time)
                self.data['nginx_rps'].append(requests_per_second.get(second_epoch, 0))
                self.data['nginx_bps_in'].append(bytes_in_per_second.get(second_epoch, 0))
                self.data['nginx_bps_out'].append(bytes_out_per_second.get(second_epoch, 0))

            print("Data loaded into self.data['nginx_rps']:", self.data['nginx_rps'])
            print("Data loaded into self.data['nginx_bps_in']:", self.data['nginx_bps_in'])
            print("Data loaded into self.data['nginx_bps_out']:", self.data['nginx_bps_out'])
            
        except Exception as e:
            print(f"Error parsing Nginx logs: {e}")
            
    def parse_cpu_logs(self):
        """Parse CPU usage logs"""
        print("Parsing CPU usage logs...")
        
        try:
            if not os.path.exists("cpu_usage.log"):
                print("CPU usage log file not found")
                return
                
            with open("cpu_usage.log", "r") as f:
                log_lines = f.readlines()
                
            cpu_usage = []
            
            for line in log_lines:
                # Skip header lines and empty lines
                if ("AM" in line or "PM" in line) and "nginx" in line:
                    # Extract CPU percentage from the line
                    parts = re.split(r'\s+', line.strip())
                    if len(parts) >= 8:
                        try:
                            # The %CPU column should be at index 7
                            cpu_percent = float(parts[7])
                            cpu_usage.append(cpu_percent)
                        except (ValueError, IndexError):
                            pass
            
            # Store in data dictionary
            self.data['nginx_cpu'] = cpu_usage
                
        except Exception as e:
            print(f"Error parsing CPU logs: {e}")
            
    def start_test(self):
        """Start all monitoring threads"""
        self.start_nginx()
        
        # Start CPU monitoring before the test
        self.start_monitor_cpu()
        
        # Give the CPU monitoring a moment to start
        time.sleep(1)
        
        # Run JMeter test
        self.run_jmeter_test()
        
        # Stop CPU monitoring after test completes
        self.stop_monitor_cpu()
        self.stop_event.set()
        
        # Parse logs
        self.parse_nginx_logs()
        self.parse_cpu_logs()
        
        self.stop_nginx()
        
    def generate_report(self):
        print(self.data)
        return
        """Generate HTML report with performance charts"""
        print("Generating performance report...")
        
        # Create time arrays for x-axis
        # Use sequence numbers if time array is not populated
        time_points = list(range(len(self.data['nginx_cpu'])))
        
        plt.figure(figsize=(12, 20))
        
        # Plot CPU Usage
        plt.subplot(5, 1, 1)
        plt.plot(time_points, self.data['nginx_cpu'])
        plt.title('Nginx Worker CPU Usage (%)')
        plt.xlabel('Time (s)')
        plt.ylabel('CPU Usage (%)')
        plt.grid(True)
        
        # Plot Nginx RPS
        plt.subplot(5, 1, 2)
        plt.plot(range(len(self.data['nginx_rps'])), self.data['nginx_rps'])
        plt.title('Nginx Requests Per Second')
        plt.xlabel('Time (s)')
        plt.ylabel('Requests/s')
        plt.grid(True)
        
        # Plot Nginx BPS
        plt.subplot(5, 1, 3)
        plt.plot(range(len(self.data['nginx_bps'])), self.data['nginx_bps'])
        plt.title('Nginx Bytes Per Second')
        plt.xlabel('Time (s)')
        plt.ylabel('Bytes/s')
        plt.grid(True)
        
        # Plot Client RPS
        plt.subplot(5, 1, 4)
        plt.plot(range(len(self.data['client_rps'])), self.data['client_rps'])
        plt.title('Client Requests Per Second')
        plt.xlabel('Time (s)')
        plt.ylabel('Requests/s')
        plt.grid(True)
        
        # Plot Client BPS
        plt.subplot(5, 1, 5)
        plt.plot(range(len(self.data['client_bps'])), self.data['client_bps'])
        plt.title('Client Bytes Per Second')
        plt.xlabel('Time (s)')
        plt.ylabel('Bytes/s')
        plt.grid(True)
        
        # Add timestamp
        plt.figtext(0.5, 0.01, f"Generated on {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}", 
                   ha='center', fontsize=10)
        
        # Adjust layout
        plt.tight_layout(rect=[0, 0.03, 1, 0.95])
        
        # Save as PNG
        plt.savefig('performance_charts.png')
        
        # Generate HTML report
        html_content = f"""
        <!DOCTYPE html>
        <html>
        <head>
            <title>Nginx Performance Benchmark Report</title>
            <style>
                body {{
                    font-family: Arial, sans-serif;
                    margin: 20px;
                    line-height: 1.6;
                }}
                h1, h2 {{
                    color: #333;
                }}
                .chart-container {{
                    margin: 20px 0;
                    text-align: center;
                }}
                .metrics-table {{
                    width: 80%;
                    margin: 20px auto;
                    border-collapse: collapse;
                }}
                .metrics-table th, .metrics-table td {{
                    padding: 8px 12px;
                    border: 1px solid #ddd;
                    text-align: left;
                }}
                .metrics-table th {{
                    background-color: #f2f2f2;
                }}
            </style>
        </head>
        <body>
            <h1>Nginx Performance Benchmark Report</h1>
            <p>Generated on: {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}</p>
            
            <h2>Performance Charts</h2>
            <div class="chart-container">
                <img src="performance_charts.png" alt="Performance Charts" width="100%">
            </div>
            
            <h2>Summary Metrics</h2>
            <table class="metrics-table">
                <tr>
                    <th>Metric</th>
                    <th>Average</th>
                    <th>Maximum</th>
                </tr>
                <tr>
                    <td>CPU Usage (%)</td>
                    <td>{sum(self.data['nginx_cpu'])/len(self.data['nginx_cpu']) if self.data['nginx_cpu'] else 'N/A':.2f}</td>
                    <td>{max(self.data['nginx_cpu']) if self.data['nginx_cpu'] else 'N/A':.2f}</td>
                </tr>
                <tr>
                    <td>Nginx RPS</td>
                    <td>{sum(self.data['nginx_rps'])/len(self.data['nginx_rps']) if self.data['nginx_rps'] else 'N/A':.2f}</td>
                    <td>{max(self.data['nginx_rps']) if self.data['nginx_rps'] else 'N/A':.2f}</td>
                </tr>
                <tr>
                    <td>Nginx BPS</td>
                    <td>{sum(self.data['nginx_bps'])/len(self.data['nginx_bps']) if self.data['nginx_bps'] else 'N/A':.2f}</td>
                    <td>{max(self.data['nginx_bps']) if self.data['nginx_bps'] else 'N/A':.2f}</td>
                </tr>
                <tr>
                    <td>Client RPS</td>
                    <td>{sum(self.data['client_rps'])/len(self.data['client_rps']) if self.data['client_rps'] else 'N/A':.2f}</td>
                    <td>{max(self.data['client_rps']) if self.data['client_rps'] else 'N/A':.2f}</td>
                </tr>
                <tr>
                    <td>Client BPS</td>
                    <td>{sum(self.data['client_bps'])/len(self.data['client_bps']) if self.data['client_bps'] else 'N/A':.2f}</td>
                    <td>{max(self.data['client_bps']) if self.data['client_bps'] else 'N/A':.2f}</td>
                </tr>
                <tr>
                    <td>Client Latency (ms)</td>
                    <td>{sum(self.data['client_latency'])/len(self.data['client_latency']) if self.data['client_latency'] else 'N/A':.2f}</td>
                    <td>{max(self.data['client_latency']) if self.data['client_latency'] else 'N/A':.2f}</td>
                </tr>
            </table>
            
            <h2>Test Configuration</h2>
            <ul>
                <li>Test Duration: {self.duration} seconds</li>
                <li>Nginx Worker PID: {self.nginx_pid}</li>
                <li>JMeter Test: {self.test_jmx_path}</li>
                <li>Test Date: {datetime.now().strftime('%Y-%m-%d')}</li>
                <li>Test Time: {datetime.now().strftime('%H:%M:%S')}</li>
            </ul>
        </body>
        </html>
        """
        
        # Write HTML report
        with open('benchmark_report.html', 'w') as f:
            f.write(html_content)
            
        print(f"Report generated: benchmark_report.html")

if __name__ == "__main__":
    parser = argparse.ArgumentParser(description='Nginx performance monitoring tool')
    parser.add_argument('--duration', type=int, default=5,
                        help='Duration of the test in seconds')
    
    args = parser.parse_args()

    benchmark = Benchmark(args.duration)
    try:
        benchmark.start_test()
        benchmark.generate_report()
    except KeyboardInterrupt:
        print("\nMonitoring interrupted. Stopping...")
        benchmark.stop_event.set()
        benchmark.stop_monitor_cpu()
        benchmark.stop_nginx()