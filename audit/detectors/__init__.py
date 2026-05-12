"""Detector implementations and the shared Finding type."""
from __future__ import annotations

from dataclasses import dataclass, field
from typing import Any


@dataclass
class Finding:
    detector:    str
    severity:    str         # one of config.SEVERITY_ORDER
    title:       str
    description: str
    frame_index: int | None = None
    metadata:    dict[str, Any] = field(default_factory=dict)

    def to_dict(self) -> dict[str, Any]:
        return {
            "detector":    self.detector,
            "severity":    self.severity,
            "title":       self.title,
            "description": self.description,
            "frame_index": self.frame_index,
            "metadata":    self.metadata,
        }


from .default_key import detect as detect_default_key   # noqa: E402
from .node_enum   import detect as detect_node_enum     # noqa: E402
from .unencrypted import detect as detect_unencrypted   # noqa: E402
from .gps_leak    import detect as detect_gps_leak      # noqa: E402

ALL_DETECTORS = {
    "default_key": detect_default_key,
    "node_enum":   detect_node_enum,
    "unencrypted": detect_unencrypted,
    "gps_leak":    detect_gps_leak,
}
