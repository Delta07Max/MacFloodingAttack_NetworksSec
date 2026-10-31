# MAC Flooding Attack & Port-Security Defense

## Project Overview

This project demonstrates a MAC flooding attack in a controlled software-defined networking (SDN) environment and implements a port-security defense mechanism with real-time attack detection and visualization.

The network is emulated using Mininet, while Open vSwitch provides switching functionality and the Ryu controller manages network traffic. A detection engine monitors source MAC address activity, identifies suspicious behavior, and triggers port-security responses. A web dashboard displays detection events and defense status.

## Objectives

- Build a virtual network using Mininet and Open vSwitch.
- Implement a Layer 2 learning-switch controller using Ryu.
- Simulate MAC flooding in an isolated lab environment.
- Detect suspicious source MAC address activity.
- Enforce port-security policies and support recovery.
- Visualize network events using a real-time dashboard.
- Capture packet-level evidence for analysis.

## Technology Stack

- **Operating System:** Debian Linux
- **Network Emulation:** Mininet
- **Virtual Switch:** Open vSwitch
- **SDN Controller:** Ryu
- **Attack Simulation:** Scapy
- **Packet Analysis:** tcpdump and Wireshark
- **Backend Dashboard:** Flask
- **Frontend Visualization:** HTML, CSS, JavaScript, and Chart.js
- **Version Control:** Git and GitHub

## Project Structure

```text
MacFloodingAttack_NetworksSec/
├── topology/       # Mininet network topology
├── controller/     # Ryu SDN controller
├── attack/         # MAC flooding simulation
├── detection/      # Attack detection engine
├── defense/        # Port-security enforcement
├── dashboard/      # Flask web dashboard
├── captures/       # Packet-capture evidence
├── logs/           # Detection and defense logs
├── tests/          # Component and integration tests
├── docs/           # Project documentation
└── README.md       # Project overview
```

## Implementation Plan

1. Configure and verify the virtual network.
2. Implement the learning-switch controller and bounded MAC table.
3. Develop the controlled MAC flooding simulation.
4. Implement source MAC activity monitoring and detection.
5. Add port-security enforcement and recovery.
6. Develop the web dashboard.
7. Test the integrated system and collect packet-capture evidence.

## Safety

All attack simulations will be performed only in the isolated Mininet lab under our control. No external networks or unauthorized devices will be targeted.

## Project Status

**Current phase:** Repository setup and environment preparation.
