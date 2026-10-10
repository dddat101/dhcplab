#!/usr/bin/env python3
"""Evidence-based measurements for TC-WQOS-01 (thin adapter to evidence_auditor)."""

import argparse
import json
import math
from pathlib import Path

from evidence_auditor import (
    EvidenceError,
    load_json,
    tshark_rows,
    packet_identity,
    rtp_jitter,
    video_jitter,
    compare_direction,
    ota_mapping,
    ota_mac_categories,
    congestion_status,
    audit_captures,
    read_capture_services as read_capture,
)


def main():
    parser = argparse.ArgumentParser(description="Write run-scoped Wireless QoS measurement context")
    parser.add_argument("--output", required=True)
    parser.add_argument("--run-id", required=True)
    parser.add_argument("--mode", required=True)
    parser.add_argument("--duration", required=True, type=float)
    parser.add_argument("--server-ip", required=True)
    parser.add_argument("--bssid", default="")
    parser.add_argument("--station-mac", default="")
    parser.add_argument("--congestion-source", default="wifi")
    parser.add_argument("--be-direction", default="downlink")
    parser.add_argument("--congestion-evidence-json", default="")
    parser.add_argument("--client-audit-json", required=True)
    parser.add_argument("--audit-profile", choices=("practical", "strict"), default="practical")
    args = vars(parser.parse_args())
    path = Path(args.pop("output"))
    temporary = path.with_suffix(".tmp")
    temporary.write_text(json.dumps(args, indent=2))
    temporary.replace(path)


if __name__ == "__main__":
    main()
