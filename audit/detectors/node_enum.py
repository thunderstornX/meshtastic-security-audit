"""Quantify node-identifier enumeration exposure.

Every Meshtastic frame exposes a 32-bit source and destination node
id in plaintext. The audit reports:

  * an inventory of every distinct source observed,
  * the per-source frame count (a rough proxy for activity / dwell
    time),
  * a ``medium`` severity finding when more than one node is
    addressable directly (i.e. unicast rather than broadcast).
"""
from __future__ import annotations

from collections import Counter
from typing import Iterable

from . import Finding

BROADCAST = 0xFFFFFFFF


def detect(frames: Iterable) -> list[Finding]:
    src_counter: Counter[int] = Counter()
    dest_counter: Counter[int] = Counter()
    direct_unicast: Counter[int] = Counter()

    for f in frames:
        src_counter[f.src] += 1
        dest_counter[f.to] += 1
        if f.to != BROADCAST:
            direct_unicast[f.to] += 1

    findings: list[Finding] = []

    if src_counter:
        findings.append(
            Finding(
                detector="node_enum",
                severity="info",
                title=f"{len(src_counter)} distinct source node id(s) observed",
                description=(
                    "Every Meshtastic frame carries the source node id in "
                    "plaintext. An observer with a receiver in range can "
                    "enumerate the mesh participants directly from the "
                    "header, independent of payload encryption."
                ),
                metadata={
                    "distinct_sources": len(src_counter),
                    "top_sources": [
                        {"node_id": f"!{n:08x}", "frames": c}
                        for n, c in src_counter.most_common(10)
                    ],
                },
            )
        )

    if direct_unicast:
        findings.append(
            Finding(
                detector="node_enum",
                severity="medium",
                title=f"{len(direct_unicast)} distinct destination node id(s) addressed directly",
                description=(
                    "Unicast destinations indicate a known correspondent set; "
                    "combined with source observation, an analyst can graph "
                    "the contact pattern of the mesh."
                ),
                metadata={
                    "distinct_unicast_destinations": len(direct_unicast),
                    "top_destinations": [
                        {"node_id": f"!{n:08x}", "frames": c}
                        for n, c in direct_unicast.most_common(10)
                    ],
                },
            )
        )

    return findings
