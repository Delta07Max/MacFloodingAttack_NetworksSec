#!/usr/bin/env python3

"""
Controlled MAC-limit test for the isolated Mininet lab.
Sends a small number of Ethernet frames with distinct
source MAC addresses through h1.
"""

from scapy.all import Ether, sendp, get_if_hwaddr
import time

INTERFACE = "h1-eth0"
TEST_MACS = [
    "02:00:00:00:00:01",
    "02:00:00:00:00:02",
    "02:00:00:00:00:03",
    "02:00:00:00:00:04",
    "02:00:00:00:00:05",
    "02:00:00:00:00:06",
]

def main():
    print(f"Interface: {INTERFACE}")
    print(f"Real interface MAC: {get_if_hwaddr(INTERFACE)}")
    print(f"Sending {len(TEST_MACS)} test frames inside Mininet...")

    for mac in TEST_MACS:
        frame = Ether(
            src=mac,
            dst="ff:ff:ff:ff:ff:ff",
            type=0x88B5
        ) / b"MAC_LIMIT_TEST"

        sendp(frame, iface=INTERFACE, verbose=False)
        print(f"Sent test frame with source MAC: {mac}")
        time.sleep(0.5)

    print("Test frames sent.")

if __name__ == "__main__":
    main()
