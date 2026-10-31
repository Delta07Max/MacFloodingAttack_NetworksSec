#!/usr/bin/env python3

"""
Mininet topology for the MAC Flooding Attack and
Port-Security Defense project.

Topology:
              s1
          / /  |  \
         h1 h2  h3  h4
"""

from mininet.topo import Topo


class MacFloodTopo(Topo):
    """One Open vSwitch connected to four virtual hosts."""

    def build(self):
        # Create the Open vSwitch.
        switch = self.addSwitch("s1")

        # Create four hosts and connect each to the switch.
        for i in range(1, 5):
            host = self.addHost(
                f"h{i}",
                ip=f"10.0.0.{i}/24"
            )

            self.addLink(host, switch)


# Register the topology so Mininet can load it by name.
topos = {
    "macflood": lambda: MacFloodTopo()
}
