"""Extract GPS coordinates from unencrypted Position payloads.

Meshtastic position packets travel inside the ``Data`` envelope on
``portnum = 3`` (POSITION_APP). The ``Position`` protobuf carries
``latitude_i`` and ``longitude_i`` as int32 values scaled by 1e7.

When such a payload is unencrypted, the audit recovers the lat/lon
pair and emits a ``critical`` finding. Encrypted payloads are not
attacked here — the toolkit is passive and does not attempt decryption.
"""
from __future__ import annotations

from typing import Iterable

from . import Finding

PORTNUM_POSITION_APP = 3
LATLON_SCALE = 1e7


def _scan_varint(buf: bytes, offset: int) -> tuple[int, int]:
    """Decode one protobuf varint starting at ``offset``.

    Returns ``(value, new_offset)``. Raises ``ValueError`` if the
    varint runs past the buffer.
    """
    value = 0
    shift = 0
    for i in range(10):
        if offset + i >= len(buf):
            raise ValueError("varint runs off end of buffer")
        b = buf[offset + i]
        value |= (b & 0x7F) << shift
        if not (b & 0x80):
            return value, offset + i + 1
        shift += 7
    raise ValueError("varint too long")


def _decode_data_envelope(payload: bytes) -> tuple[int, bytes] | None:
    """Extract ``(portnum, inner_payload)`` from a Data protobuf.

    Returns ``None`` if the buffer does not look like a Data envelope.
    """
    if not payload or payload[0] != 0x08:
        return None
    try:
        portnum, off = _scan_varint(payload, 1)
    except ValueError:
        return None

    # Find the payload sub-message (field 2, wire type 2). Walk until
    # we hit tag 0x12, then read the length-delimited body.
    while off < len(payload):
        tag = payload[off]
        off += 1
        field_number = tag >> 3
        wire_type    = tag & 0x07
        if field_number == 2 and wire_type == 2:
            try:
                length, off = _scan_varint(payload, off)
            except ValueError:
                return None
            if off + length > len(payload):
                return None
            return portnum, payload[off:off + length]
        # Skip unknown fields. Three wire types matter here: 0 (varint),
        # 2 (length-delimited), 5 (fixed32).
        if wire_type == 0:
            try:
                _, off = _scan_varint(payload, off)
            except ValueError:
                return None
        elif wire_type == 2:
            try:
                length, off = _scan_varint(payload, off)
            except ValueError:
                return None
            off += length
        elif wire_type == 5:
            off += 4
        else:
            return None
    return None


def _decode_position(buf: bytes) -> dict[str, float] | None:
    """Pull lat/lon from a Position protobuf body, if present.

    Returns ``None`` if neither field is found in the first 64 bytes.
    The full Position message has many optional fields; we only care
    about ``latitude_i`` (field 1, sfixed32) and ``longitude_i``
    (field 2, sfixed32). Both are length-prefix-less, 4 bytes each.
    """
    lat = lon = None
    off = 0
    while off < min(len(buf), 64):
        tag = buf[off]
        off += 1
        field_number = tag >> 3
        wire_type    = tag & 0x07
        if wire_type == 5:  # 32-bit fixed
            if off + 4 > len(buf):
                break
            value = int.from_bytes(buf[off:off + 4], "little", signed=True)
            off += 4
            if field_number == 1 and lat is None:
                lat = value / LATLON_SCALE
            elif field_number == 2 and lon is None:
                lon = value / LATLON_SCALE
            if lat is not None and lon is not None:
                break
        elif wire_type == 0:
            try:
                value = 0
                shift = 0
                while off < len(buf):
                    b = buf[off]; off += 1
                    value |= (b & 0x7F) << shift
                    if not (b & 0x80):
                        break
                    shift += 7
                if field_number == 1 and lat is None:
                    lat = value / LATLON_SCALE
                elif field_number == 2 and lon is None:
                    lon = value / LATLON_SCALE
                if lat is not None and lon is not None:
                    break
            except Exception:
                break
        elif wire_type == 2:
            if off >= len(buf):
                break
            length = buf[off]; off += 1
            off += length
        else:
            break

    if lat is None or lon is None:
        return None
    if not (-90.0 <= lat <= 90.0) or not (-180.0 <= lon <= 180.0):
        return None
    return {"latitude": lat, "longitude": lon}


def detect(frames: Iterable) -> list[Finding]:
    findings: list[Finding] = []
    leaks = 0

    for f in frames:
        envelope = _decode_data_envelope(f.payload)
        if envelope is None:
            continue
        portnum, inner = envelope
        if portnum != PORTNUM_POSITION_APP:
            continue
        coords = _decode_position(inner)
        if coords is None:
            continue

        leaks += 1
        # Record on the frame for the reporter.
        f.decoded_port = portnum
        f.decoded_position = coords

        findings.append(
            Finding(
                detector="gps_leak",
                severity="critical",
                title=f"GPS coordinates recovered from unencrypted position payload",
                description=(
                    f"Frame {f.pcap_index} carries a position protobuf on "
                    f"port {portnum} that was not encrypted at capture "
                    f"time. Latitude {coords['latitude']:+.5f}, "
                    f"longitude {coords['longitude']:+.5f}."
                ),
                frame_index=f.pcap_index,
                metadata={
                    "latitude":  coords["latitude"],
                    "longitude": coords["longitude"],
                    "src":       f.src,
                    "channel":   f.channel,
                },
            )
        )

    if leaks:
        findings.append(
            Finding(
                detector="gps_leak",
                severity="critical",
                title="GPS leakage summary",
                description=(
                    f"Recovered GPS coordinates from {leaks} unencrypted "
                    f"position payload(s). Each leak is sufficient to place "
                    f"the broadcasting node on a map."
                ),
                metadata={"leaks": leaks},
            )
        )
    return findings
