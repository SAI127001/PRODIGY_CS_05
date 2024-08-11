import scapy.all as scapy
import argparse
from scapy.layers import http  # Import the HTTP layer from scapy
import pyfiglet

# ANSI color codes
RED = "\033[91m"
GREEN = "\033[92m"
YELLOW = "\033[93m"
BLUE = "\033[94m"
CYAN = "\033[96m"
RESET = "\033[0m"

def display_banner():
    """
    Display the banner with the tool's name and author.
    """
    banner = pyfiglet.figlet_format("PACKET ANALYZER")
    print(f"{BLUE}{banner}{RESET}")
    print(f"{YELLOW}                               ~ Made by Terukula Sai {RESET}\n")

def get_interface():
    """
    Parse the command-line arguments to get the network interface to sniff on.
    """
    parser = argparse.ArgumentParser(description="Packet sniffer to capture network traffic.")
    parser.add_argument("-i", "--interface", required=True, help="Specify the interface to sniff packets on.")
    args = parser.parse_args()
    return args.interface

def display_packet_info(packet):
    """
    Display the source and destination IP addresses and protocol type for each packet.
    """
    src_ip = packet[scapy.IP].src
    dst_ip = packet[scapy.IP].dst
    protocol = packet[scapy.IP].proto
    print(f"{CYAN}[+] Source IP: {src_ip} | Destination IP: {dst_ip} | Protocol: {protocol}{RESET}")

def handle_http_request(packet):
    """
    Handle and display HTTP request information.
    """
    http_layer = packet[http.HTTPRequest]
    host = http_layer.Host.decode()
    path = http_layer.Path.decode()
    print(f"{GREEN}[+] HTTP Request: {host}{path}{RESET}")

    if packet.haslayer(scapy.Raw):
        load = packet[scapy.Raw].load.decode('utf-8', 'ignore')
        keywords = ["username", "password", "pass", "email"]
        if any(keyword in load for keyword in keywords):
            print(f"{RED}[+] Possible Credential Found: {load}{RESET}")

def handle_tcp_udp_payload(packet, protocol):
    """
    Handle and display TCP/UDP payloads, if present.
    """
    if packet.haslayer(scapy.Raw):
        try:
            payload = packet[scapy.Raw].load.decode('utf-8', 'ignore')
            print(f"{YELLOW}[+] {protocol} Payload: {payload}{RESET}")
        except UnicodeDecodeError:
            print(f"{RED}[-] Unable to decode {protocol} payload.{RESET}")

def process_packet(packet):
    """
    Process each packet to extract and display relevant information.
    """
    if packet.haslayer(scapy.IP):
        display_packet_info(packet)

        if packet.haslayer(http.HTTPRequest):
            handle_http_request(packet)

        if packet.haslayer(scapy.TCP):
            handle_tcp_udp_payload(packet, "TCP")
        elif packet.haslayer(scapy.UDP):
            handle_tcp_udp_payload(packet, "UDP")

def start_sniffing(interface):
    """
    Start sniffing on the specified network interface.
    """
    scapy.sniff(iface=interface, store=False, prn=process_packet)

if __name__ == "__main__":
    display_banner()
    iface = get_interface()
    start_sniffing(iface)
