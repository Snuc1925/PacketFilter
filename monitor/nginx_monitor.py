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
import mpld3
import numpy as np

class Test:
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

        self.stop_nginx()
        


class Report:
    def __init__(self):
        self.nginx_cpu_usage_log_file = "cpu_usage.log"
        self.nginx_access_log_file = "/var/log/nginx/access.log"
        self.jmeter_results_file = "results.jtl"

        self.data = {
            'nginx': {
                'cpu': {
                    'time': [],
                    'value': []
                },
                'rps': {
                    'time': [],
                    'value': []
                },
                'bps': {
                    'time': [],
                    'value': []
                }              
            }, 

            'jmeter': {
                'rps': {
                    'time': [],
                    'value': []
                },
                'bps': {
                    'time': [],
                    'value': []
                }             
            }
        }

    def parse_jmeter_results(self):
        print("------------------------------------------------------")
        """Process JMeter results file (.jtl)"""
        print(f"Processing JMeter results from {self.jmeter_results_file}...")

        try:
            if not os.path.exists(self.jmeter_results_file):
                print("JMeter results file not found")
                return

            with open(self.jmeter_results_file, 'r') as f:
                lines = f.readlines()[1:]  # Skip header

            if not lines:
                print("No data in JMeter results file")
                return

            requests_by_second = {}
            bytes_by_second = {}

            for line in lines:
                parts = line.strip().split(",")
                if len(parts) < 11:
                    continue
                try:
                    # timestamp in ms → convert to s
                    timestamp_ms = int(parts[0])
                    second = timestamp_ms // 1000

                    sent_bytes = int(parts[10])  # sentBytes column

                    requests_by_second[second] = requests_by_second.get(second, 0) + 1
                    bytes_by_second[second] = bytes_by_second.get(second, 0) + sent_bytes

                except ValueError:
                    continue

            if not requests_by_second:
                print("No valid data parsed from JMeter results.")
                return

            # Sort by time
            sorted_seconds = sorted(requests_by_second.keys())

            # Fill in data arrays with human-readable time
            for second in sorted_seconds:
                human_time = datetime.fromtimestamp(second).strftime("%H:%M:%S")

                self.data['jmeter']['rps']['time'].append(human_time)
                self.data['jmeter']['rps']['value'].append(requests_by_second[second])

                self.data['jmeter']['bps']['time'].append(human_time)
                self.data['jmeter']['bps']['value'].append(bytes_by_second[second])

            print("Parsed JMeter RPS:", self.data['jmeter']['rps'])
            print("Parsed JMeter BPS:", self.data['jmeter']['bps'])
            print("RPS count:", len(self.data['jmeter']['rps']['time']))
            print("BPS count:", len(self.data['jmeter']['bps']['time']))

        except Exception as e:
            print(f"Error parsing JMeter results: {e}")
        print("------------------------------------------------------")
        


    def parse_nginx_logs(self):
        print("------------------------------------------------------")
        print("Parsing Nginx access logs...")
        try:
            if not os.path.exists(self.nginx_access_log_file):
                print(f"Error: Nginx access log file not found at {self.nginx_access_log_file}")
                return

            with open(self.nginx_access_log_file, "r", encoding='utf-8', errors='ignore') as f:
                log_lines = f.readlines()

            if not log_lines:
                print("No data in Nginx access logs.")
                return

            # Group by second
            requests_by_second = {}
            bytes_by_second = {}

            for line in log_lines:
                parts = line.strip().split()
                if len(parts) < 3:
                    continue
                try:
                    timestamp = float(parts[1])       # 1758268008.083
                    second = int(timestamp)           # -> 1758268008
                    bytes_sent = int(parts[2])        # 116

                    requests_by_second[second] = requests_by_second.get(second, 0) + 1
                    bytes_by_second[second] = bytes_by_second.get(second, 0) + bytes_sent
                except ValueError:
                    continue

            if not requests_by_second:
                print("No valid data parsed from Nginx logs.")
                return

            # Sort by time
            sorted_seconds = sorted(requests_by_second.keys())

            # Fill data arrays with real timestamps
            for second in sorted_seconds:
                human_time = datetime.fromtimestamp(second).strftime("%H:%M:%S")

                self.data['nginx']['rps']['time'].append(human_time)
                self.data['nginx']['rps']['value'].append(requests_by_second[second])

                self.data['nginx']['bps']['time'].append(human_time)
                self.data['nginx']['bps']['value'].append(bytes_by_second[second])

            print("Parsed Nginx RPS:", self.data['nginx']['rps'])
            print("Parsed Nginx BPS:", self.data['nginx']['bps'])
            print("Length of RPS:", len(self.data['nginx']['rps']['time']))
            print("Length of BPS:", len(self.data['nginx']['bps']['time']))

        except Exception as e:
            print(f"Error parsing Nginx logs: {e}")
        print("------------------------------------------------------")


    def parse_cpu_logs(self):
        print("------------------------------------------------------")
        """Parse CPU usage logs"""
        print("Parsing CPU usage logs...")
        try:
            if not os.path.exists(self.nginx_cpu_usage_log_file):
                print("CPU usage log file not found")
                return
            
            with open(self.nginx_cpu_usage_log_file, "r") as f:
                log_lines = f.readlines()

            for line in log_lines:
                # Bỏ qua header hoặc dòng trống
                if re.match(r'^\d{2}:\d{2}:\d{2}', line) and "nginx" in line:
                    parts = re.split(r'\s+', line.strip())
                    if len(parts) >= 9:
                        try:
                            timestamp = parts[0]
                            cpu_percent = float(parts[7].replace(",", "."))
                            self.data['nginx']['cpu']['time'].append(timestamp)
                            self.data['nginx']['cpu']['value'].append(cpu_percent)
                        except (ValueError, IndexError):
                            pass

            print("Parsed CPU data:", self.data['nginx']['cpu'])
            print("Length of time:", len(self.data['nginx']['cpu']['time']))
            print("Length of value:", len(self.data['nginx']['cpu']['value']))

        except Exception as e:
            print(f"Error parsing CPU logs: {e}")
        print("------------------------------------------------------")

    def generate_html(self):
        html_content = """
        <!DOCTYPE html>
        <html>
        <head>
            <title>Performance Test Report</title>
            <style>
                body {{
                    font-family: Arial, sans-serif;
                    margin: 20px;
                }}
                .chart-container {{
                    margin-bottom: 30px;
                }}
                .metrics-table {{
                    border-collapse: collapse;
                    width: 100%;
                    margin-top: 10px;
                }}
                .metrics-table th, .metrics-table td {{
                    border: 1px solid #ddd;
                    padding: 8px;
                    text-align: center;
                }}
                .metrics-table th {{
                    background-color: #f2f2f2;
                }}
                h2 {{
                    color: #333;
                }}
                .timestamp {{
                    color: #666;
                    font-size: 14px;
                    margin-bottom: 20px;
                }}
            </style>
        </head>
        <body>
            <h1>Performance Test Report</h1>
            <div class="timestamp">Generated on: {}</div>
        """.format(datetime.now().strftime('%Y-%m-%d %H:%M:%S'))

        
        # Function to create a chart and metrics table for a given dataset
        def create_chart_with_metrics(title, time_data, value_data):
            if not time_data or not value_data or len(time_data) == 0:
                return f"<div class='chart-container'><h2>{title}</h2><p>No data available</p></div>"
                
            # Calculate metrics
            min_val = min(value_data)
            max_val = max(value_data)
            avg_val = sum(value_data) / len(value_data) if value_data else 0
            
            # Create figure and axis
            fig, ax = plt.subplots(figsize=(10, 6))
            
            # Plot data line with label
            ax.plot(time_data, value_data, '-o', markersize=3, label="Data")
            
            # Plot horizontal lines with labels
            ax.axhline(y=min_val, color='g', linestyle='--', alpha=0.7, label=f"Min: {min_val:.2f}")
            ax.axhline(y=max_val, color='r', linestyle='--', alpha=0.7, label=f"Max: {max_val:.2f}")
            ax.axhline(y=avg_val, color='b', linestyle='--', alpha=0.7, label=f"Avg: {avg_val:.2f}")
            
            # Labels and title
            ax.set_xlabel('Time')
            ax.set_ylabel('Value')
            ax.set_title(title)
            
            # Add legend properly
            ax.legend()
            
            # Convert plot to HTML
            chart_html = mpld3.fig_to_html(fig)
            plt.close(fig)
            
            # Create metrics summary table
            metrics_table = f"""
            <table class="metrics-table">
                <tr>
                    <th>Minimum</th>
                    <th>Maximum</th>
                    <th>Average</th>
                </tr>
                <tr>
                    <td>{min_val:.2f}</td>
                    <td>{max_val:.2f}</td>
                    <td>{avg_val:.2f}</td>
                </tr>
            </table>
            """
            
            return f"""
            <div class="chart-container">
                <h2>{title}</h2>
                {chart_html}
                <h3>Metrics Summary</h3>
                {metrics_table}
            </div>
            """

        
        # Generate charts for each metric
        charts = []
        
        # Nginx CPU chart
        charts.append(create_chart_with_metrics(
            "Nginx CPU Usage",
            self.data['nginx']['cpu']['time'],
            self.data['nginx']['cpu']['value']
        ))
        
        # Nginx RPS chart
        charts.append(create_chart_with_metrics(
            "Nginx Requests Per Second",
            self.data['nginx']['rps']['time'],
            self.data['nginx']['rps']['value']
        ))
        
        # Nginx BPS chart
        charts.append(create_chart_with_metrics(
            "Nginx Bytes Per Second",
            self.data['nginx']['bps']['time'],
            self.data['nginx']['bps']['value']
        ))
        
        # JMeter RPS chart
        charts.append(create_chart_with_metrics(
            "JMeter Requests Per Second",
            self.data['jmeter']['rps']['time'],
            self.data['jmeter']['rps']['value']
        ))
        
        # JMeter BPS chart
        charts.append(create_chart_with_metrics(
            "JMeter Bytes Per Second",
            self.data['jmeter']['bps']['time'],
            self.data['jmeter']['bps']['value']
        ))
        
        # Add all charts to HTML content
        html_content += "".join(charts)
        
        # Close HTML tags
        html_content += """
        </body>
        </html>
        """
        
        # Write HTML to file
        with open('performance_report.html', 'w') as f:
            f.write(html_content)
        
        print(f"Report generated: performance_report.html")

    def generate_report(self):
        # generate .html file 
        self.parse_jmeter_results()
        self.parse_nginx_logs()
        self.parse_cpu_logs()
        self.generate_html()


if __name__ == "__main__":
    parser = argparse.ArgumentParser(description='Nginx performance monitoring tool')
    parser.add_argument('--duration', type=int, default=60,
                        help='Duration of the test in seconds')
    
    args = parser.parse_args()

    test = Test(args.duration)
    try:
        test.start_test()
        report = Report()
        report.generate_report()
    except KeyboardInterrupt:
        print("\nMonitoring interrupted. Stopping...")
        test.stop_event.set()
        test.stop_monitor_cpu()
        test.stop_nginx()