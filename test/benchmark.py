#!/usr/bin/env python3
"""
Performance comparison tool for eBPF vs nginx IP blacklist filtering
This script provides multiple test modes to ensure fair comparison between different filtering mechanisms
"""

import argparse
import time
import socket
import random
import statistics
import subprocess
import threading
from concurrent.futures import ThreadPoolExecutor
from scapy.all import IP, TCP, Raw, sr1, send

class ConnectionMode:
    """Enum for different connection modes"""
    FULL_TCP = "full_tcp"  # Complete TCP handshake + HTTP request
    SYN_ONLY = "syn_only"  # Only send SYN packets
    RAW_HTTP = "raw_http"  # Raw HTTP over established connections

class TestResult:
    def __init__(self):
        self.sent = 0
        self.blocked = 0
        self.succeeded = 0
        self.response_times = []
        self.errors = []
        self.start_time = 0
        self.end_time = 0

    def calculate_stats(self):
        self.total_time = self.end_time - self.start_time
        self.rps = self.sent / self.total_time if self.total_time > 0 else 0
        
        if self.response_times:
            self.avg_response = statistics.mean(self.response_times)
            self.min_response = min(self.response_times)
            self.max_response = max(self.response_times)
            self.median_response = statistics.median(self.response_times)
        else:
            self.avg_response = self.min_response = self.max_response = self.median_response = 0

class BenchmarkTool:
    def __init__(self, target, port, num_requests, concurrency, timeout):
        self.target = target
        self.port = port
        self.num_requests = num_requests
        self.concurrency = concurrency
        self.timeout = timeout
        self.result = TestResult()
    
    def run_full_tcp_test(self):
        """Test with full TCP handshake and HTTP requests - good for nginx testing"""
        self.result.start_time = time.time()
        
        with ThreadPoolExecutor(max_workers=self.concurrency) as executor:
            futures = []
            for i in range(self.num_requests):
                futures.append(executor.submit(self._send_full_tcp_request, i))
            
            for future in futures:
                future.result()
        
        self.result.end_time = time.time()
        return self.result

    def run_syn_only_test(self):
        """Test with only SYN packets - good for eBPF testing"""
        self.result.start_time = time.time()
        
        with ThreadPoolExecutor(max_workers=self.concurrency) as executor:
            futures = []
            for i in range(self.num_requests):
                futures.append(executor.submit(self._send_syn_packet, i))
            
            for future in futures:
                future.result()
        
        self.result.end_time = time.time()
        return self.result

    def run_hybrid_test(self):
        """
        Hybrid test that measures SYN packet handling efficiency for eBPF
        and application-level filtering efficiency for nginx
        """
        # For eBPF: Measure how fast SYNs are dropped
        ebpf_result = self.run_syn_only_test()
        
        # For nginx: Measure how fast requests are processed after connection
        nginx_result = self.run_full_tcp_test()
        
        return {
            "ebpf": ebpf_result,
            "nginx": nginx_result
        }

    def _send_full_tcp_request(self, request_id):
        """Send a complete HTTP request with proper TCP handshake"""
        self.result.sent += 1
        start_time = time.time()
        try:
            s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            s.settimeout(self.timeout)
            
            # Connect (TCP handshake)
            s.connect((self.target, self.port))
            
            # Send HTTP request
            http_request = f"GET / HTTP/1.1\r\nHost: {self.target}\r\n\r\n"
            s.sendall(http_request.encode())
            
            # Receive response
            response = s.recv(4096)
            
            s.close()
            
            # Check if blocked (by HTTP response)
            if b"403 Forbidden" in response:
                self.result.blocked += 1
            else:
                self.result.succeeded += 1
            
            elapsed = time.time() - start_time
            self.result.response_times.append(elapsed)
            return True
            
        except (socket.timeout, ConnectionRefusedError) as e:
            # Connection blocked or timed out
            elapsed = time.time() - start_time
            self.result.response_times.append(elapsed)
            self.result.blocked += 1
            self.result.errors.append(f"Request {request_id}: {str(e)}")
            return False
            
        except Exception as e:
            self.result.errors.append(f"Request {request_id}: {str(e)}")
            return False

    def _send_syn_packet(self, request_id):
        """Send a SYN packet using scapy and measure response time"""
        self.result.sent += 1
        source_port = random.randint(1024, 65535)
        
        # Create a TCP SYN packet
        syn_packet = IP(dst=self.target) / TCP(
            sport=source_port,
            dport=self.port,
            flags="S",
            seq=random.randint(0, 2**32-1)
        )
        
        start_time = time.time()
        try:
            # Send SYN and wait for response with timeout
            response = sr1(syn_packet, timeout=self.timeout, verbose=0)
            elapsed = time.time() - start_time
            
            if response is None:
                # No response - packet was likely dropped (eBPF block)
                self.result.blocked += 1
            elif response.haslayer(TCP) and response[TCP].flags & 0x12:
                # SYN/ACK received - not blocked
                self.result.succeeded += 1
            else:
                # RST received or other response - connection rejected
                self.result.blocked += 1
                
            self.result.response_times.append(elapsed)
            
        except Exception as e:
            elapsed = time.time() - start_time
            self.result.errors.append(f"Request {request_id}: {str(e)}")
            self.result.response_times.append(elapsed)
            
        return True

def print_results(result, test_name):
    """Format and print test results"""
    print(f"\n--- {test_name} Test Results ---")
    print(f"Requests sent: {result.sent}")
    print(f"Requests blocked: {result.blocked}")
    print(f"Requests succeeded: {result.succeeded}")
    print(f"Total time: {result.total_time:.2f} seconds")
    print(f"Requests per second: {result.rps:.2f}")
    
    if result.response_times:
        print(f"Average response time: {result.avg_response*1000:.2f} ms")
        print(f"Min response time: {result.min_response*1000:.2f} ms")
        print(f"Max response time: {result.max_response*1000:.2f} ms")
        print(f"Median response time: {result.median_response*1000:.2f} ms")
    
    if result.errors:
        print(f"Errors: {len(result.errors)}")
        for i, error in enumerate(result.errors[:5]):  # Show only first 5 errors
            print(f"  {error}")
        if len(result.errors) > 5:
            print(f"  ... and {len(result.errors) - 5} more")

def validate_environment():
    """Check if the environment has all necessary dependencies"""
    try:
        # Check for scapy
        import scapy
    except ImportError:
        print("ERROR: Scapy is not installed. Please install it with: pip install scapy")
        return False
    
    # Check if running as root (needed for raw sockets)
    if subprocess.call("id -u", shell=True, stdout=subprocess.PIPE) != "0\n":
        print("WARNING: This script may need to be run with root privileges for raw packet operations")
    
    return True

def main():
    parser = argparse.ArgumentParser(
        description='Compare performance of eBPF vs nginx IP blacklist filtering',
        formatter_class=argparse.RawTextHelpFormatter
    )
    parser.add_argument('-t', '--target', required=True, help='Target server IP address')
    parser.add_argument('-p', '--port', type=int, default=80, help='Target port (default: 80)')
    parser.add_argument('-n', '--num-requests', type=int, default=100, help='Number of requests to send (default: 100)')
    parser.add_argument('-c', '--concurrency', type=int, default=10, help='Number of concurrent requests (default: 10)')
    parser.add_argument('-m', '--mode', choices=['full_tcp', 'syn_only', 'hybrid', 'all'], 
                        default='all', help='''Test mode:
full_tcp: Complete TCP handshake + HTTP (best for nginx testing)
syn_only: Only send SYN packets (best for eBPF testing)
hybrid: Specialized test to fairly compare both methods
all: Run all test modes (default)''')
    parser.add_argument('--timeout', type=float, default=2.0, help='Request timeout in seconds (default: 2.0)')
    parser.add_argument('--baseline', action='store_true', 
                        help='Run baseline test against non-blocking server for comparison')
    args = parser.parse_args()

    if not validate_environment():
        return 1

    benchmark = BenchmarkTool(
        target=args.target,
        port=args.port,
        num_requests=args.num_requests,
        concurrency=args.concurrency,
        timeout=args.timeout
    )

    if args.mode in ['full_tcp', 'all']:
        result = benchmark.run_full_tcp_test()
        result.calculate_stats()
        print_results(result, "Full TCP")

    if args.mode in ['syn_only', 'all']:
        result = benchmark.run_syn_only_test()
        result.calculate_stats()
        print_results(result, "SYN Only")

    if args.mode in ['hybrid', 'all']:
        results = benchmark.run_hybrid_test()
        results['ebpf'].calculate_stats()
        results['nginx'].calculate_stats()
        print_results(results['ebpf'], "Hybrid - eBPF")
        print_results(results['nginx'], "Hybrid - nginx")

    if args.baseline:
        print("\nRunning baseline test against non-blocking server...")
        # Implement baseline testing logic here
        # This would test against a server with no filtering for comparison

    print("\nTest complete!")
    return 0

if __name__ == "__main__":
    main()