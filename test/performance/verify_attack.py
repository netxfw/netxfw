from scapy.all import IP, UDP, Ether, sendp, conf
import time

# Target IP (local interface IP)
target_ip = "192.168.5.3"
# Source IP to simulate attack
attacker_ip = "1.2.3.4"
interface = "ens18"

print(f"🚀 Starting HIGH-SPEED simulated attack from {attacker_ip} to {target_ip} on {interface}...")

# Create packet template
packet = Ether() / IP(src=attacker_ip, dst=target_ip) / UDP(sport=12345, dport=80)

# Get L2 socket for faster sending
s = conf.L2socket(iface=interface)

# Send packets in large batches
batch_size = 1000
total_sent = 0

try:
    while total_sent < 1000000:
        # Use a list of packets for faster sending in some scapy versions, 
        # but even just repeated send() on the same socket is faster.
        for _ in range(batch_size):
            s.send(packet)
        total_sent += batch_size
        print(f"Sent {total_sent} packets...")
        # Small sleep to avoid completely locking up the Python process if needed, 
        # but we WANT to exceed 2000 pps.
except KeyboardInterrupt:
    print("Stopped by user.")

print("✅ Attack simulation finished.")
s.close()
