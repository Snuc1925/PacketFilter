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

class NginxMonitor:
    def __init__(self, duration=10):
        base_dir = os.path.dirname(os.path.abspath(__file__))  # thư mục chứa nginx_monitor.py
        jmeter_dir = os.path.join(base_dir, "apache-jmeter-5.6.3")
        self.jmeter_path = os.path.join(jmeter_dir, "bin", "jmeter")
        self.test_jmx_path = os.path.join(jmeter_dir, "test.jmx")
        self.duration = duration
        self.nginx_pid = None
        self.data = {
            'time': [],
            'nginx_cpu': [],
            'nginx_rps': [],
            'nginx_bps': [],
            'client_rps': [],
            'client_bps': [],
            'client_latency': []
        }
        self.stop_event = threading.Event()
        
    def start_nginx(self):
        """Start Nginx with the provided configuration"""
        print("Starting Nginx...")
        # subprocess.run(["sudo", "nginx", "-c", os.path.abspath("nginx.conf")])
        
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
        subprocess.run(["sudo", "nginx", "-s", "stop"])
        
    def monitor_nginx_cpu(self):
        """Monitor Nginx worker CPU usage"""
        print("Starting CPU monitoring...")
        start_time = time.time()
        last_time = start_time
        
        try:
            proc = psutil.Process(self.nginx_pid)
            while not self.stop_event.is_set():
                current_time = time.time() - start_time
                cpu_percent = proc.cpu_percent(interval=1.0)
                
                self.data['time'].append(current_time)
                self.data['nginx_cpu'].append(cpu_percent)
                
                # Small sleep to prevent CPU hogging
                time.sleep(0.01)
        except Exception as e:
            print(f"Error monitoring CPU: {e}")
            
    def monitor_nginx_traffic(self):
        """Monitor Nginx incoming requests using log file"""
        print("Starting Nginx traffic monitoring...")
        start_time = time.time()
        last_check_time = start_time
        last_size = 0
        last_count = 0
        
        try:
            while not self.stop_event.is_set():
                current_time = time.time()
                
                # Every second, calculate metrics
                if current_time - last_check_time >= 1:
                    # Get log file stats
                    try:
                        log_size = os.path.getsize("/var/log/nginx/access.log")
                        
                        # Count requests in the log file
                        result = subprocess.run(
                            ["sudo", "wc", "-l", "/var/log/nginx/access.log"],
                            capture_output=True, text=True
                        )
                        request_count = int(result.stdout.strip().split()[0])
                        
                        # Calculate RPS and BPS
                        elapsed = current_time - last_check_time
                        rps = (request_count - last_count) / elapsed
                        bps = (log_size - last_size) / elapsed
                        
                        self.data['nginx_rps'].append(rps)
                        self.data['nginx_bps'].append(bps)
                        
                        # Update counters
                        last_count = request_count
                        last_size = log_size
                        last_check_time = current_time
                    except Exception as e:
                        print(f"Error reading log: {e}")
                
                # Small sleep to prevent CPU hogging
                time.sleep(0.1)
        except Exception as e:
            print(f"Error monitoring Nginx traffic: {e}")
            
    def run_jmeter_test(self):
        """Run JMeter test from victim-ns namespace"""
        print("Starting JMeter test...")
        
        jmeter_cmd = [
            "sudo", "ip", "netns", "exec", "victim-ns",
            self.jmeter_path, "-n", "-t", self.test_jmx_path
        ]
        
        try:
            jmeter_proc = subprocess.Popen(
                jmeter_cmd,
                stdout=subprocess.PIPE,
                stderr=subprocess.PIPE,
                text=True
            )
            
            # Process JMeter output in real-time
            start_time = time.time()
            client_rps = []
            client_bps = []
            client_latency = []
            
            for line in jmeter_proc.stdout:
                if "summary =" in line:
                    # Extract metrics from JMeter summary
                    current_time = time.time() - start_time
                    
                    # Extract RPS
                    rps_match = re.search(r'(\d+\.\d+)/s', line)
                    if rps_match:
                        client_rps.append((current_time, float(rps_match.group(1))))
                    
                    # Extract throughput (KB/sec)
                    bps_match = re.search(r'(\d+\.\d+) KB/sec', line)
                    if bps_match:
                        client_bps.append((current_time, float(bps_match.group(1)) * 1024))  # Convert to bytes
                    
                    # Extract average latency
                    latency_match = re.search(r'Avg:\s+(\d+)', line)
                    if latency_match:
                        client_latency.append((current_time, float(latency_match.group(1))))
                    
            # Wait for JMeter to finish
            jmeter_proc.wait()
            
            # Process client metrics
            for time_point, rps in client_rps:
                self.data['client_rps'].append(rps)
                
            for time_point, bps in client_bps:
                self.data['client_bps'].append(bps)
                
            for time_point, latency in client_latency:
                self.data['client_latency'].append(latency)
                
        except Exception as e:
            print(f"Error running JMeter test: {e}")
            
    def start_monitoring(self):
        """Start all monitoring threads"""
        self.start_nginx()
        
        # Start monitoring threads
        cpu_thread = threading.Thread(target=self.monitor_nginx_cpu)
        traffic_thread = threading.Thread(target=self.monitor_nginx_traffic)
        
        cpu_thread.start()
        traffic_thread.start()
        
        # Run JMeter test
        self.run_jmeter_test()
        
        # Stop monitoring after test completes
        self.stop_event.set()
        cpu_thread.join()
        traffic_thread.join()
        
        self.stop_nginx()
        
    def generate_report(self):
        """Generate HTML report with visualizations"""
        print("Generating report...")
        
        # Create figure with subplots
        fig, axs = plt.subplots(3, 2, figsize=(15, 15))
        fig.suptitle('Nginx Performance Monitoring Report', fontsize=16)
        
        # Plot 1: Nginx CPU Usage
        axs[0, 0].plot(self.data['time'], self.data['nginx_cpu'])
        axs[0, 0].set_title('Nginx Worker CPU Usage (%)')
        axs[0, 0].set_xlabel('Time (seconds)')
        axs[0, 0].set_ylabel('CPU %')
        axs[0, 0].grid(True)
        
        # Plot 2: Nginx RPS
        axs[0, 1].plot(self.data['time'], self.data['nginx_rps'])
        axs[0, 1].set_title('Nginx Requests Per Second')
        axs[0, 1].set_xlabel('Time (seconds)')
        axs[0, 1].set_ylabel('RPS')
        axs[0, 1].grid(True)
        
        # Plot 3: Nginx BPS
        axs[1, 0].plot(self.data['time'], self.data['nginx_bps'])
        axs[1, 0].set_title('Nginx Bytes Per Second')
        axs[1, 0].set_xlabel('Time (seconds)')
        axs[1, 0].set_ylabel('BPS')
        axs[1, 0].grid(True)
        
        # Plot 4: Client RPS
        if self.data['client_rps']:
            time_range = list(range(len(self.data['client_rps'])))
            axs[1, 1].plot(time_range, self.data['client_rps'])
            axs[1, 1].set_title('Client Requests Per Second')
            axs[1, 1].set_xlabel('Time (seconds)')
            axs[1, 1].set_ylabel('RPS')
            axs[1, 1].grid(True)
        
        # Plot 5: Client BPS
        if self.data['client_bps']:
            time_range = list(range(len(self.data['client_bps'])))
            axs[2, 0].plot(time_range, self.data['client_bps'])
            axs[2, 0].set_title('Client Bytes Per Second')
            axs[2, 0].set_xlabel('Time (seconds)')
            axs[2, 0].set_ylabel('BPS')
            axs[2, 0].grid(True)
        
        # Plot 6: Client Latency
        if self.data['client_latency']:
            time_range = list(range(len(self.data['client_latency'])))
            axs[2, 1].plot(time_range, self.data['client_latency'])
            axs[2, 1].set_title('Client Request Latency')
            axs[2, 1].set_xlabel('Time (seconds)')
            axs[2, 1].set_ylabel('Latency (ms)')
            axs[2, 1].grid(True)
        
        # Adjust layout
        plt.tight_layout(rect=[0, 0, 1, 0.96])
        
        # Save as HTML
        timestamp = datetime.now().strftime("%Y%m%d-%H%M%S")
        html_path = f"nginx_report_{timestamp}.html"
        
        with open(html_path, 'w') as f:
            f.write(f"""<!DOCTYPE html>
            <html>
            <head>
                <title>Nginx Performance Report</title>
                <style>
                    body {{ font-family: Arial, sans-serif; margin: 20px; }}
                    h1 {{ color: #333; }}
                    .timestamp {{ color: #777; margin-bottom: 20px; }}
                    img {{ max-width: 100%; height: auto; }}
                </style>
            </head>
            <body>
                <h1>Nginx Performance Monitoring Report</h1>
                <div class="timestamp">Generated on: {datetime.now().strftime("%Y-%m-%d %H:%M:%S")}</div>
                <img src="data:image/png;base64,{self.get_base64_image()}" alt="Performance Metrics">
                <h2>Summary</h2>
                <ul>
                    <li>Average Nginx CPU Usage: {sum(self.data['nginx_cpu'])/len(self.data['nginx_cpu']):.2f}%</li>
                    <li>Average Nginx RPS: {sum(self.data['nginx_rps'])/len(self.data['nginx_rps']):.2f}</li>
                    <li>Average Nginx BPS: {sum(self.data['nginx_bps'])/len(self.data['nginx_bps']):.2f}</li>
                    {"<li>Average Client RPS: " + f"{sum(self.data['client_rps'])/len(self.data['client_rps']):.2f}</li>" if self.data['client_rps'] else ""}
                    {"<li>Average Client BPS: " + f"{sum(self.data['client_bps'])/len(self.data['client_bps']):.2f}</li>" if self.data['client_bps'] else ""}
                    {"<li>Average Client Latency: " + f"{sum(self.data['client_latency'])/len(self.data['client_latency']):.2f} ms</li>" if self.data['client_latency'] else ""}
                </ul>
            </body>
            </html>
            """)
        
        plt.savefig("report_graph.png")
        print(f"Report generated: {html_path}")
        
    def get_base64_image(self):
        """Convert the matplotlib figure to base64 for HTML embedding"""
        import io
        import base64
        
        buffer = io.BytesIO()
        plt.savefig(buffer, format='png')
        buffer.seek(0)
        image_base64 = base64.b64encode(buffer.getvalue()).decode('utf-8')
        buffer.close()
        return image_base64

if __name__ == "__main__":
    parser = argparse.ArgumentParser(description='Nginx performance monitoring tool')
    # parser.add_argument('--jmeter-path', default='~/apache-jmeter-5.6.3/bin/jmeter', 
    #                     help='Path to JMeter executable')
    # parser.add_argument('--jmx-path', default='~/apache-jmeter-5.6.3/test.jmx',
    #                     help='Path to JMeter test file (.jmx)')
    parser.add_argument('--duration', type=int, default=30,
                        help='Duration of the test in seconds')
    
    args = parser.parse_args()
    
    # Expand home directory in paths
    # jmeter_path = os.path.expanduser(args.jmeter_path)
    # jmx_path = os.path.expanduser(args.jmx_path)
    
    # Check if files exist
    # if not os.path.isfile(jmeter_path):
    #     print(f"Error: JMeter executable not found at {jmeter_path}")
    #     exit(1)
        
    # if not os.path.isfile(jmx_path):
    #     print(f"Error: JMeter test file not found at {jmx_path}")
    #     exit(1)
    
    monitor = NginxMonitor(args.duration)
    try:
        monitor.start_monitoring()
        monitor.generate_report()
    except KeyboardInterrupt:
        print("\nMonitoring interrupted. Stopping...")
        monitor.stop_event.set()
        monitor.stop_nginx()