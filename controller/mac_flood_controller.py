#!/usr/bin/env python3
"""
MAC Flooding Detection and Port-Security Controller.

Runs inside an isolated Mininet lab using OpenFlow 1.3.

Features:
- Learns source MAC addresses on switch ports.
- Enforces a maximum number of distinct MAC addresses per port.
- Blocks a port when its MAC limit is exceeded.
- Automatically recovers the port after a timeout.
- Writes security events to a JSONL log.
- Publishes blocked-port state for the Flask dashboard.
"""

import json
import os
import time
from collections import defaultdict

from os_ken.base import app_manager
from os_ken.controller import ofp_event
from os_ken.controller.handler import (
    CONFIG_DISPATCHER,
    MAIN_DISPATCHER,
    DEAD_DISPATCHER,
    set_ev_cls,
)
from os_ken.ofproto import ofproto_v1_3
from os_ken.lib import hub


class MacFloodController(app_manager.OSKenApp):
    """Learning switch with MAC-limit port security."""

    OFP_VERSIONS = [ofproto_v1_3.OFP_VERSION]

    MAX_MACS_PER_PORT = 5
    RECOVERY_SECONDS = 30

    LOG_FILE = "logs/security_events.jsonl"
    PORT_STATUS_FILE = "logs/port_status.json"

    def __init__(self, *args, **kwargs):
        super(MacFloodController, self).__init__(*args, **kwargs)

        # MAC addresses learned on each switch port.
        # Structure: learned_macs[dpid][port] = set(MAC addresses)
        self.learned_macs = defaultdict(
            lambda: defaultdict(set)
        )

        # Ports currently blocked by this controller.
        # Structure: blocked_ports[dpid] = set(port numbers)
        self.blocked_ports = defaultdict(set)

        # Recovery deadlines, keyed by (switch ID, port number).
        self.recovery_deadlines = {}

        # Connected OpenFlow switches.
        self.datapaths = {}

        # Host-facing and switch port hardware addresses.
        self.port_hw_addresses = defaultdict(dict)

        # Ensure the logs directory exists.
        os.makedirs("logs", exist_ok=True)

        # Publish an initial status file for the dashboard.
        self.write_port_status()

        self.logger.info(
            "MAC Flood Controller started. MAC limit=%s, recovery=%ss",
            self.MAX_MACS_PER_PORT,
            self.RECOVERY_SECONDS,
        )

        # Background task checks whether blocked ports can recover.
        self.recovery_thread = hub.spawn(
            self.recovery_loop
        )

    # ---------------------------------------------------------
    # Logging and dashboard status
    # ---------------------------------------------------------

    def log_event(
        self,
        event_type,
        dpid,
        port_no,
        mac=None,
        details="",
    ):
        """Write a security event to the JSONL log."""

        event = {
            "timestamp": time.time(),
            "event": event_type,
            "switch": str(dpid),
            "port": port_no,
            "mac": mac,
            "details": details,
        }

        try:
            with open(
                self.LOG_FILE,
                "a",
                encoding="utf-8",
            ) as log_file:
                log_file.write(
                    json.dumps(event) + "\n"
                )

        except OSError as exc:
            self.logger.error(
                "Could not write security event: %s",
                exc,
            )

        self.logger.info(
            "SECURITY EVENT: %s",
            event,
        )

    def write_port_status(self):
        """
        Publish the controller's blocked-port state.

        The dashboard reads this file directly, without running
        privileged Open vSwitch commands.
        """

        status = {
            "timestamp": time.time(),
            "blocked_ports": [
                {
                    "switch": str(dpid),
                    "port": port_no,
                }
                for dpid, ports in self.blocked_ports.items()
                for port_no in sorted(ports)
            ],
        }

        temporary_file = self.PORT_STATUS_FILE + ".tmp"

        try:
            with open(
                temporary_file,
                "w",
                encoding="utf-8",
            ) as status_file:
                json.dump(status, status_file)
                status_file.write("\n")

            # Atomic replacement prevents the dashboard from
            # reading a partially written JSON file.
            os.replace(
                temporary_file,
                self.PORT_STATUS_FILE,
            )

        except OSError as exc:
            self.logger.error(
                "Could not write port status file: %s",
                exc,
            )

            try:
                if os.path.exists(temporary_file):
                    os.remove(temporary_file)
            except OSError:
                pass

    # ---------------------------------------------------------
    # OpenFlow switch connection and initialization
    # ---------------------------------------------------------

    @set_ev_cls(
        ofp_event.EventOFPSwitchFeatures,
        CONFIG_DISPATCHER,
    )
    def switch_features_handler(self, ev):
        """Install the table-miss flow when a switch connects."""

        datapath = ev.msg.datapath
        ofproto = datapath.ofproto
        parser = datapath.ofproto_parser

        self.datapaths[datapath.id] = datapath

        # Send packets to the controller when no flow matches.
        match = parser.OFPMatch()

        actions = [
            parser.OFPActionOutput(
                ofproto.OFPP_CONTROLLER,
                ofproto.OFPCML_NO_BUFFER,
            )
        ]

        instructions = [
            parser.OFPInstructionActions(
                ofproto.OFPIT_APPLY_ACTIONS,
                actions,
            )
        ]

        flow_mod = parser.OFPFlowMod(
            datapath=datapath,
            priority=0,
            match=match,
            instructions=instructions,
        )

        datapath.send_msg(flow_mod)

        # Request port descriptions to learn interface names
        # and hardware addresses.
        request = parser.OFPPortDescStatsRequest(
            datapath,
            0,
        )

        datapath.send_msg(request)

        self.logger.info(
            "Switch connected: %s",
            datapath.id,
        )

    @set_ev_cls(
        ofp_event.EventOFPPortDescStatsReply,
        MAIN_DISPATCHER,
    )
    def port_description_handler(self, ev):
        """Record switch port hardware addresses."""

        datapath = ev.msg.datapath
        dpid = datapath.id

        for port in ev.msg.body:
            self.port_hw_addresses[dpid][port.port_no] = (
                port.hw_addr
            )

        self.logger.info(
            "Recorded hardware addresses for switch %s ports: %s",
            dpid,
            sorted(self.port_hw_addresses[dpid].keys()),
        )

    @set_ev_cls(
        ofp_event.EventOFPStateChange,
        [MAIN_DISPATCHER, DEAD_DISPATCHER],
    )
    def switch_state_change_handler(self, ev):
        """Track connected switches."""

        datapath = ev.datapath

        if ev.state == MAIN_DISPATCHER:
            self.datapaths[datapath.id] = datapath

        elif ev.state == DEAD_DISPATCHER:
            self.datapaths.pop(
                datapath.id,
                None,
            )

            self.logger.info(
                "Switch disconnected: %s",
                datapath.id,
            )

    # ---------------------------------------------------------
    # Packet processing and MAC learning
    # ---------------------------------------------------------

    @set_ev_cls(
        ofp_event.EventOFPPacketIn,
        MAIN_DISPATCHER,
    )
    def packet_in_handler(self, ev):
        """Learn MAC addresses and forward packets."""

        msg = ev.msg
        datapath = msg.datapath
        dpid = datapath.id

        ofproto = datapath.ofproto
        parser = datapath.ofproto_parser

        in_port = msg.match.get("in_port")

        if in_port is None:
            return

        # Ignore packets received on ports blocked by us.
        if in_port in self.blocked_ports.get(dpid, set()):
            return

        packet_data = msg.data

        from os_ken.lib.packet import packet
        from os_ken.lib.packet import ethernet
        from os_ken.lib.packet import ether_types

        pkt = packet.Packet(packet_data)

        eth = pkt.get_protocol(
            ethernet.ethernet
        )

        if eth is None:
            return

        # Ignore LLDP frames.
        if eth.ethertype == ether_types.ETH_TYPE_LLDP:
            return

        src_mac = eth.src
        dst_mac = eth.dst

        # Learn source MAC on the incoming port.
        known_macs = self.learned_macs[dpid][in_port]

        if src_mac not in known_macs:
            known_macs.add(src_mac)

            self.logger.info(
                "Learned MAC %s on switch %s port %s (%s/%s)",
                src_mac,
                dpid,
                in_port,
                len(known_macs),
                self.MAX_MACS_PER_PORT,
            )

            # Enforce the configured MAC limit.
            if len(known_macs) > self.MAX_MACS_PER_PORT:
                self.block_port(
                    datapath,
                    in_port,
                    src_mac,
                )
                return

        # Learn source-to-port mapping for forwarding.
        # Search other ports on the switch for the destination.
        destination_port = None

        for port_no, mac_set in self.learned_macs[dpid].items():
            if dst_mac in mac_set:
                destination_port = port_no
                break

        # Unknown destination: flood to all ports except input.
        if destination_port is None:
            actions = [
                parser.OFPActionOutput(
                    ofproto.OFPP_FLOOD
                )
            ]

        else:
            # Do not forward back to the incoming port.
            if destination_port == in_port:
                return

            # Do not forward to a blocked port.
            if (
                destination_port
                in self.blocked_ports.get(dpid, set())
            ):
                actions = [
                    parser.OFPActionOutput(
                        ofproto.OFPP_FLOOD
                    )
                ]
            else:
                actions = [
                    parser.OFPActionOutput(
                        destination_port
                    )
                ]

        # Send the packet.
        out = parser.OFPPacketOut(
            datapath=datapath,
            buffer_id=msg.buffer_id,
            in_port=in_port,
            actions=actions,
            data=(
                None
                if msg.buffer_id != ofproto.OFP_NO_BUFFER
                else packet_data
            ),
        )

        datapath.send_msg(out)

    # ---------------------------------------------------------
    # Port blocking and recovery
    # ---------------------------------------------------------

    def block_port(
        self,
        datapath,
        port_no,
        offending_mac,
    ):
        """Administratively block a port that exceeds its MAC limit."""

        dpid = datapath.id

        # Do not block the same port repeatedly.
        if port_no in self.blocked_ports[dpid]:
            return

        self.log_event(
            "PORT_LIMIT_EXCEEDED",
            dpid,
            port_no,
            offending_mac,
            (
                "MAC limit of "
                f"{self.MAX_MACS_PER_PORT} exceeded"
            ),
        )

        # Remove existing flows that could forward traffic
        # through the port being blocked.
        parser = datapath.ofproto_parser

        match = parser.OFPMatch(
            in_port=port_no
        )

        flow_delete = parser.OFPFlowMod(
            datapath=datapath,
            command=datapath.ofproto.OFPFC_DELETE,
            out_port=datapath.ofproto.OFPP_ANY,
            out_group=datapath.ofproto.OFPG_ANY,
            match=match,
        )

        datapath.send_msg(flow_delete)

        # Administratively disable the switch port.
        port_hw_addr = self.port_hw_addresses.get(
            dpid,
            {},
        ).get(port_no)

        if port_hw_addr is None:
            self.logger.error(
                "Cannot block switch %s port %s: "
                "hardware address is unknown",
                dpid,
                port_no,
            )
            return

        port_mod = parser.OFPPortMod(
            datapath=datapath,
            port_no=port_no,
            hw_addr=port_hw_addr,
            config=datapath.ofproto.OFPPC_PORT_DOWN,
            mask=datapath.ofproto.OFPPC_PORT_DOWN,
            advertise=0,
        )

        datapath.send_msg(port_mod)

        self.blocked_ports[dpid].add(port_no)

        self.recovery_deadlines[(dpid, port_no)] = (
            time.time() + self.RECOVERY_SECONDS
        )

        self.log_event(
            "PORT_BLOCKED",
            dpid,
            port_no,
            offending_mac,
            (
                f"Exceeded {self.MAX_MACS_PER_PORT} distinct "
                f"MAC addresses; port blocked for "
                f"{self.RECOVERY_SECONDS} seconds"
            ),
        )

        self.write_port_status()

        self.logger.warning(
            "Blocked switch %s port %s for %s seconds",
            dpid,
            port_no,
            self.RECOVERY_SECONDS,
        )

    def recover_port(
        self,
        dpid,
        port_no,
    ):
        """Re-enable a blocked port after the recovery timeout."""

        datapath = self.datapaths.get(dpid)

        if datapath is None:
            self.logger.warning(
                "Cannot recover switch %s port %s: "
                "switch is disconnected",
                dpid,
                port_no,
            )
            return

        port_hw_addr = self.port_hw_addresses.get(
            dpid,
            {},
        ).get(port_no)

        if port_hw_addr is None:
            self.logger.error(
                "Cannot recover switch %s port %s: "
                "hardware address is unknown",
                dpid,
                port_no,
            )
            return

        parser = datapath.ofproto_parser

        port_mod = parser.OFPPortMod(
            datapath=datapath,
            port_no=port_no,
            hw_addr=port_hw_addr,
            config=0,
            mask=datapath.ofproto.OFPPC_PORT_DOWN,
            advertise=0,
        )

        datapath.send_msg(port_mod)

        self.blocked_ports[dpid].discard(port_no)

        self.recovery_deadlines.pop(
            (dpid, port_no),
            None,
        )

        # Clear learned MACs on the recovered port so the
        # next traffic can be relearned.
        self.learned_macs[dpid][port_no].clear()

        self.log_event(
            "PORT_RECOVERED",
            dpid,
            port_no,
            None,
            (
                "Port administratively re-enabled "
                "after recovery timeout"
            ),
        )

        self.write_port_status()

        self.logger.info(
            "Recovered switch %s port %s",
            dpid,
            port_no,
        )

    def recovery_loop(self):
        """Periodically recover ports whose timeout has expired."""

        while True:
            now = time.time()

            expired = [
                (dpid, port_no)
                for (dpid, port_no), deadline
                in list(self.recovery_deadlines.items())
                if now >= deadline
            ]

            for dpid, port_no in expired:
                self.recover_port(
                    dpid,
                    port_no,
                )

            hub.sleep(1)

