import time
from scapy.all import IP, TCP, sr1
import argparse

def scan(dest_ip, port, delay):
    pckt = IP(dst = dest_ip) / TCP(dport = port, flags = 'S')
    response = sr1(pckt,verbose=False, timeout = 1)

    if response.haslayer(TCP):
        if response.getlayer(TCP).flags == 0x12:
            print(f"Port: {port} is open")
        elif response.getlayer(TCP).flags == 0x14:
            print(f"Port: {port} is closed")
    else:
        print(f"Port: {port} is filtered")

def arg_parser():
    parser = argparse.ArgumentParser(description="TCP SYN Scan using Scapy")
    parser.add_argument("target", help="Target IP Address")
    parser.add_argument("--start", type=int, help="Start port for scanning (default: 1)", default=1)
    parser.add_argument("--end", type=int, help="End port for scanning (default: 65535)", default=65535)
    parser.add_argument("--delay", type=int, help="Delay in milliseconds between scans (default: 0)", default=0)
    args = parser.parse_args()
    return (args.target, args.start, args.end, args.delay)

def check_invalid_input(start_port, end_port, delay):
    if delay <0:
        print(f"{delay} is invalid. Switching to default value of 0")
        delay = 0
    
    if(65535 < start_port or start_port < 1):
        raise ValueError("Invalid Start Port")

    if(65535 < end_port or end_port < 1 or start_port > end_port):
        raise ValueError("Invalid End Port")

    return (delay, start_port, end_port)

def main():
    dest_ip, start_port, end_port, delay = arg_parser()
    try:
        delay, start_port, end_port = check_invalid_input(start_port,end_port,delay)
    except ValueError as e:
        print(f"Exiting Program due to Error: {e}")
        exit()
    print(f" Target: {dest_ip}, Start Port: {start_port}, End Port: {end_port}, Delay: {delay}")

    for cur_port in range(start_port, end_port+1):
        scan(dest_ip, cur_port, delay)
        time.sleep (delay/1000)

main()