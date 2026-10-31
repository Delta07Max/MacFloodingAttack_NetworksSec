#!/usr/bin/env python3

"""
Flask backend for the MAC Flooding Detection Dashboard.

Features:
- Reads security events from the controller's JSONL log.
- Reads controller-published blocked-port state from JSON.
- Provides security-event and status APIs.
- Reports recent MAC-limit violations.
- Provides port-security summary statistics.

The controller publishes logs/port_status.json whenever a port
is blocked or recovered. This application does not require sudo.
"""

import json
import os
import time
from datetime import datetime, timezone

from flask import Flask, jsonify, render_template

app = Flask(__name__)

BASE_DIR = os.path.dirname(
    os.path.dirname(os.path.abspath(__file__))
)

LOG_FILE = os.path.join(
    BASE_DIR,
    "logs",
    "security_events.jsonl",
)

PORT_STATUS_FILE = os.path.join(
    BASE_DIR,
    "logs",
    "port_status.json",
)

# A MAC-limit violation counts as recent for five minutes.
RECENT_ATTACK_SECONDS = 300

# Mininet topology uses switch s1 and host-facing ports 1 through 4.
EXPECTED_SWITCH_PORTS = [
    {
        "switch": "1",
        "port": port_number,
        "name": f"s1-eth{port_number}",
    }
    for port_number in range(1, 5)
]


def read_security_events():
    """Read valid security events from the JSONL log."""

    events = []

    if not os.path.exists(LOG_FILE):
        return events

    try:
        with open(
            LOG_FILE,
            "r",
            encoding="utf-8",
        ) as file:
            for line in file:
                line = line.strip()

                if not line:
                    continue

                try:
                    event = json.loads(line)

                    timestamp = event.get("timestamp")

                    if timestamp is not None:
                        timestamp = float(timestamp)
                        event["timestamp"] = timestamp

                        event["time_utc"] = datetime.fromtimestamp(
                            timestamp,
                            tz=timezone.utc,
                        ).strftime("%Y-%m-%d %H:%M:%S UTC")

                    events.append(event)

                except (
                    json.JSONDecodeError,
                    TypeError,
                    ValueError,
                    OverflowError,
                ):
                    # Ignore malformed entries.
                    continue

    except OSError:
        app.logger.exception(
            "Could not read the security event log"
        )

    # Ensure chronological order.
    events.sort(
        key=lambda event: event.get("timestamp", 0)
    )

    return events


def read_controller_port_status():
    """
    Read the latest blocked-port state published by the controller.

    The returned state reflects the controller's recorded decisions.
    It is not an independent query of the physical link state.
    """

    if not os.path.exists(PORT_STATUS_FILE):
        return {
            "available": False,
            "timestamp": None,
            "blocked_ports": [],
            "error": "Controller port-status file has not been created.",
        }

    try:
        with open(
            PORT_STATUS_FILE,
            "r",
            encoding="utf-8",
        ) as file:
            data = json.load(file)

        blocked_ports = []

        for entry in data.get("blocked_ports", []):
            switch_id = entry.get("switch")
            port_number = entry.get("port")

            if switch_id is None or port_number is None:
                continue

            try:
                port_number = int(port_number)
            except (TypeError, ValueError):
                continue

            blocked_ports.append({
                "switch": str(switch_id),
                "port": port_number,
            })

        return {
            "available": True,
            "timestamp": data.get("timestamp"),
            "blocked_ports": blocked_ports,
            "error": None,
        }

    except (
        OSError,
        json.JSONDecodeError,
        TypeError,
        ValueError,
    ) as error:
        app.logger.warning(
            "Could not read controller port status: %s",
            error,
        )

        return {
            "available": False,
            "timestamp": None,
            "blocked_ports": [],
            "error": "Controller port-status data is unavailable or invalid.",
        }


def build_controller_port_table(controller_status):
    """
    Build the dashboard port table from the controller status file.

    ADMIN_DOWN means the controller currently records the port as
    blocked. LIVE means the controller does not record it as blocked.
    LIVE does not independently guarantee physical link availability.
    """

    if not controller_status["available"]:
        return {
            "available": False,
            "ports": [],
            "error": controller_status["error"],
            "source": "controller_status_file",
        }

    blocked_set = {
        (entry["switch"], entry["port"])
        for entry in controller_status["blocked_ports"]
    }

    ports = []

    for port_info in EXPECTED_SWITCH_PORTS:
        switch_id = port_info["switch"]
        port_number = port_info["port"]

        if (switch_id, port_number) in blocked_set:
            status = "ADMIN_DOWN"
        else:
            status = "LIVE"

        ports.append({
            **port_info,
            "status": status,
        })

    return {
        "available": True,
        "ports": ports,
        "error": None,
        "source": "controller_status_file",
        "updated_at": controller_status["timestamp"],
    }


def get_port_states(events):
    """
    Reconstruct historical port states from security events.

    Returns a dictionary keyed by (switch ID, port number).
    """

    port_states = {}

    for event in events:
        event_type = event.get("event")

        if event_type not in (
            "PORT_BLOCKED",
            "PORT_RECOVERED",
        ):
            continue

        switch_id = event.get("switch")
        port_number = event.get("port")

        if switch_id is None or port_number is None:
            continue

        key = (
            str(switch_id),
            str(port_number),
        )

        if event_type == "PORT_BLOCKED":
            port_states[key] = {
                "switch": str(switch_id),
                "port": port_number,
                "status": "BLOCKED",
                "timestamp": event.get("timestamp"),
            }

        elif event_type == "PORT_RECOVERED":
            port_states[key] = {
                "switch": str(switch_id),
                "port": port_number,
                "status": "RECOVERED",
                "timestamp": event.get("timestamp"),
            }

    return port_states


def build_security_summary(events):
    """Build the dashboard security summary."""

    now = time.time()

    controller_status = read_controller_port_status()

    # Use the controller's current state when available.
    if controller_status["available"]:
        blocked_ports = controller_status["blocked_ports"]
        status_source = "controller_status_file"
    else:
        # Fallback for startup or missing status-file situations.
        historical_states = get_port_states(events)

        blocked_ports = [
            {
                "switch": state["switch"],
                "port": state["port"],
            }
            for state in historical_states.values()
            if state["status"] == "BLOCKED"
        ]

        status_source = "security_event_log_fallback"

    violations = [
        event
        for event in events
        if event.get("event") == "PORT_LIMIT_EXCEEDED"
        and isinstance(
            event.get("timestamp"),
            (int, float),
        )
    ]

    latest_violation = (
        violations[-1]
        if violations
        else None
    )

    recent_attack = False
    seconds_since_attack = None

    if latest_violation is not None:
        seconds_since_attack = max(
            0,
            int(now - latest_violation["timestamp"]),
        )

        recent_attack = (
            seconds_since_attack <= RECENT_ATTACK_SECONDS
        )

    if blocked_ports:
        status = "ALERT"
    elif recent_attack:
        status = "RECENT ATTACK DETECTED"
    else:
        status = "NORMAL"

    return {
        "status": status,
        "blocked_ports": blocked_ports,
        "blocked_port_count": len(blocked_ports),
        "total_events": len(events),
        "total_violations": len(violations),
        "recent_attack": recent_attack,
        "seconds_since_last_attack": seconds_since_attack,
        "recent_attack_window_seconds": RECENT_ATTACK_SECONDS,
        "latest_attack": latest_violation,
        "latest_event": events[-1] if events else None,
        "status_source": status_source,
        "live_switch": build_controller_port_table(
            controller_status
        ),
    }


@app.route("/")
def dashboard():
    """Render the dashboard page."""

    return render_template("index.html")


@app.route("/api/events")
def get_events():
    """Return security events, newest first."""

    events = read_security_events()

    return jsonify({
        "total_events": len(events),
        "events": list(reversed(events)),
    })


@app.route("/api/status")
def get_status():
    """Return the current security summary."""

    events = read_security_events()

    return jsonify(
        build_security_summary(events)
    )


if __name__ == "__main__":
    # Local-machine access only.
    app.run(
        host="127.0.0.1",
        port=5000,
        debug=False,
    )

