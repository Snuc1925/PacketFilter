#!/usr/bin/env python3
"""
Scapy Packet Generator

This script generates a .pcap file containing N packets with configurable parameters:
- Variable number of packets from blacklisted IPs
- Multiple protocol types (HTTP, HTTPS, DNS, ICMP, UDP)
- Variable packet sizes
- Protocol-appropriate payloads

Usage:
    python packet_generator.py -n <number_of_packets> -r <blacklist_rate> -o <output_file>
"""

import argparse
import random
import string
import ipaddress
import os
import sys

# More selective imports from scapy to avoid matplotlib dependency issues
from scapy.all import conf
conf.matplotlib = False  # Disable matplotlib

from scapy.layers.inet import IP, TCP, UDP, ICMP
from scapy.layers.dns import DNS, DNSQR
from scapy.layers.l2 import Ether
from scapy.packet import Raw
from scapy.utils import wrpcap

def generate_random_ip(exclude_list):
    """Generate a random IP not in the exclude list"""
    while True:
        # Generate IPs in private ranges for safety
        ip_ranges = [
            "10.0.0.0/8",
            "172.16.0.0/12",
            "192.168.0.0/16"
        ]
        selected_range = random.choice(ip_ranges)
        network = ipaddress.IPv4Network(selected_range)
        ip = str(ipaddress.IPv4Address(random.randint(
            int(network.network_address),
            int(network.broadcast_address)
        )))
        
        if ip not in exclude_list and ip != "192.168.100.1":  # Ensure it's not the destination
            return ip

def random_string(size):
    """Generate a random string of specified size"""
    return ''.join(random.choices(string.ascii_letters + string.digits, k=size))

def generate_random_payload(min_size=200, max_size=1400):
    """Generate random payload data of specified size"""
    size = random.randint(min_size, max_size)
    return random_string(size)

def generate_http_packet(src_ip, dst_ip="192.168.100.1"):
    """Generate an HTTP packet"""
    http_methods = ["GET", "POST", "PUT", "DELETE"]
    http_paths = ["/index.html", "/api/v1/users", "/login", "/images/logo.png", "/styles.css"]
    http_hosts = ["example.com", "api.service.com", "cdn.content.com"]
    
    method = random.choice(http_methods)
    path = random.choice(http_paths)
    host = random.choice(http_hosts)
    
    # Create the base packet
    packet = Ether() / IP(src=src_ip, dst=dst_ip) / TCP(sport=random.randint(1024, 65535), dport=80)
    
    # Add HTTP layer
    http_payload = f"{method} {path} HTTP/1.1\r\nHost: {host}\r\nUser-Agent: Mozilla/5.0\r\n\r\n"
    if method in ["POST", "PUT"]:
        payload_size = random.randint(20, 1000)
        http_payload += generate_random_payload(payload_size, payload_size)
    
    return packet / Raw(load=http_payload)

def generate_https_packet(src_ip, dst_ip="192.168.100.1"):
    """Generate an HTTPS packet (TLS over TCP)"""
    # TLS handshake simulation
    tls_types = [
        b'\x16\x03\x01',  # Handshake
        b'\x17\x03\x03',  # Application data
        b'\x15\x03\x03'   # Alert
    ]
    
    tls_header = random.choice(tls_types)
    payload_size = random.randint(50, 1200)
    random_bytes = os.urandom(payload_size)  # Use os.urandom instead of random.randbytes for compatibility
    tls_data = tls_header + bytes([0, payload_size >> 8, payload_size & 0xFF]) + random_bytes
    
    return Ether() / IP(src=src_ip, dst=dst_ip) / TCP(sport=random.randint(1024, 65535), dport=443) / Raw(load=tls_data)

def generate_dns_packet(src_ip, dst_ip="192.168.100.1"):
    """Generate a DNS packet"""
    domains = ["example.com", "google.com", "github.com", "aws.amazon.com", "microsoft.com"]
    domain = random.choice(domains)
    
    return (Ether() / 
            IP(src=src_ip, dst=dst_ip) / 
            UDP(sport=random.randint(1024, 65535), dport=53) / 
            DNS(rd=1, qd=DNSQR(qname=domain)))

def generate_icmp_packet(src_ip, dst_ip="192.168.100.1"):
    """Generate an ICMP packet"""
    # ICMP echo request (ping)
    payload_size = random.randint(32, 1400)
    payload = random_string(payload_size)
    
    return Ether() / IP(src=src_ip, dst=dst_ip) / ICMP(type=8, code=0) / Raw(load=payload)

def generate_udp_packet(src_ip, dst_ip="192.168.100.1"):
    """Generate a UDP packet with random payload"""
    payload_size = random.randint(50, 1400)
    payload = random_string(payload_size)
    
    return (Ether() / 
            IP(src=src_ip, dst=dst_ip) / 
            UDP(sport=random.randint(1024, 65535), dport=random.randint(1024, 65535)) / 
            Raw(load=payload))

def main():
    parser = argparse.ArgumentParser(description='Generate PCAP file with configurable packet parameters')
    parser.add_argument('-n', '--num_packets', type=int, default=100, help='Number of packets to generate')
    parser.add_argument('-r', '--blacklist_rate', type=float, default=0.2, 
                        help='Ratio of packets from blacklisted IPs (0.0-1.0)')
    parser.add_argument('-o', '--output', type=str, default='generated_packets.pcap',
                        help='Output PCAP file path')
    args = parser.parse_args()
    
    # Validate arguments
    if args.num_packets <= 0:
        parser.error("Number of packets must be positive")
    if not 0 <= args.blacklist_rate <= 1:
        parser.error("Blacklist rate must be between 0.0 and 1.0")
    
    # Initialize blacklist
    blacklist_ip = ["192.168.100.2"]
    # You can add more blacklisted IPs here
    
    # Calculate number of blacklisted packets
    blacklist_count = int(args.num_packets * args.blacklist_rate)
    normal_count = args.num_packets - blacklist_count
    
    print(f"Generating {args.num_packets} packets:")
    print(f" - {blacklist_count} packets from blacklisted IPs: {', '.join(blacklist_ip)}")
    print(f" - {normal_count} packets from random IPs")
    print(f"Output will be saved to: {args.output}")
    
    # Packet generation functions
    packet_generators = [
        generate_http_packet,
        generate_https_packet,
        generate_dns_packet,
        generate_icmp_packet,
        generate_udp_packet
    ]
    
    packets = []
    
    # Generate blacklisted packets
    for _ in range(blacklist_count):
        src_ip = random.choice(blacklist_ip)
        generator_func = random.choice(packet_generators)
        packets.append(generator_func(src_ip))
    
    # Generate normal packets
    for _ in range(normal_count):
        src_ip = generate_random_ip(blacklist_ip)
        generator_func = random.choice(packet_generators)
        packets.append(generator_func(src_ip))
    
    # Shuffle packets to mix blacklisted and normal packets
    random.shuffle(packets)
    
    # Write packets to pcap file
    wrpcap(args.output, packets)
    print(f"Generated {len(packets)} packets and saved to {args.output}")

if __name__ == "__main__":
    main()