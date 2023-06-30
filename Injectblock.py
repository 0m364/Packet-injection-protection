from scapy.all import *

def packet_handler(packet):
    # Check if the packet contains any suspicious payload
    if packet.haslayer(Raw):
        payload = packet[Raw].load

        # Define the signatures of known packet injection patterns
        signatures = [
            b'\x90\x90\x90',  # Example signature 1
            b'\x41\x41\x41'   # Example signature 2
            # Add more signatures if needed
        ]

        for signature in signatures:
            if signature in payload:
                # Block the packet
                packet.drop()
                print("Blocked suspicious packet injection:", payload)
                break

# Start sniffing packets on your network interface
sniff(prn=packet_handler, filter="tcp")

# Replace the "filter" parameter with your desired network filter if needed
