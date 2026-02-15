import json
import time
from scapy.all import sniff, IP, TCP, UDP, DNS
from collections import defaultdict
from scapy.all import Raw # Add Raw to your imports

# --- 1. Load Rules from JSON ---
def load_signatures():
    try:
        with open("rules.json", "r") as f:
            return json.load(f)
    except FileNotFoundError:
        return {}

SIGNATURE_DB = load_signatures()

# --- 2. The Signature Checking Function ---
def check_signatures(packet, src_ip):
    # Only check if the packet has a 'Raw' layer (where data is stored)
    if packet.haslayer(Raw):
        payload = str(packet[Raw].load).upper() # Convert to uppercase for matching
        
        for attack_name, keywords in SIGNATURE_DB.items():
            for key in keywords:
                if key.upper() in payload:
                    log_alert(f"SIGNATURE: {attack_name}", src_ip, f"Found pattern: {key}")
                    return True
    return False

# --- 3. Update your Callback ---
def packet_callback(packet):
    if packet.haslayer(IP):
        src_ip = packet[IP].src
        
        # Run Signature Check
        check_signatures(packet, src_ip)
        
        # ... keep your existing Port Scan and SYN Flood logic below this ...


# --- CONFIGURATION ---
INTERFACE = "en1"  # Matches your Wi-Fi interface from the screenshot
ALERT_LOG = "alerts.json"

# Trackers for detection logic
syn_counts = defaultdict(int)
port_tracker = defaultdict(set)

def log_alert(attack_type, source_ip, details):
    alert = {
        "timestamp": time.strftime("%Y-%m-%d %H:%M:%S"),
        "type": attack_type,
        "source": source_ip,
        "details": details
    }
    with open(ALERT_LOG, "a") as f:
        f.write(json.dumps(alert) + "\n")
    print(f" [ALERT] {attack_type} from {source_ip}!")

def packet_callback(packet):
    if packet.haslayer(IP):
        src_ip = packet[IP].src
        
        # 1. SYN Flood Detection
        if packet.haslayer(TCP) and packet[TCP].flags == "S":
            syn_counts[src_ip] += 1
            if syn_counts[src_ip] > 50: # Threshold: 50 SYN packets
                log_alert("SYN Flood", src_ip, "Excessive TCP SYN flags detected")
                syn_counts[src_ip] = 0 # Reset after alert

        # 2. Port Scan Detection
        if packet.haslayer(TCP) or packet.haslayer(UDP):
            dst_port = packet.sport # Checking source ports for scanning patterns
            port_tracker[src_ip].add(dst_port)
            if len(port_tracker[src_ip]) > 20:
                log_alert("Port Scan", src_ip, f"Scanned {len(port_tracker[src_ip])} unique ports")
                port_tracker[src_ip] = set() # Reset

        # 3. DNS Query Extraction (Phase 1 Goal)
        if packet.haslayer(DNS) and packet.getlayer(DNS).qr == 0:
            query = packet.getlayer(DNS).qd.qname.decode()
            print(f"🔍 DNS Query: {query} from {src_ip}")
        


print(f" Starting Net-Sentinel on {INTERFACE}...")
sniff(iface=INTERFACE, prn=packet_callback, store=0)