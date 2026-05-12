"""meshtastic-audit — analyse a Meshtastic PCAP capture."""
from __future__ import annotations

import json
import sys
from pathlib import Path

import click

# Allow `python cli.py …` from the repo root.
sys.path.insert(0, str(Path(__file__).resolve().parent))

from audit.pcap_parser import parse_pcap
from audit.detectors    import ALL_DETECTORS, Finding
from audit.reporter     import to_html, to_json
from config             import SEVERITY_ORDER


_SEVERITY_RANK = {s: i for i, s in enumerate(SEVERITY_ORDER)}


@click.command(name="meshtastic-audit")
@click.option("--pcap", "pcap_path", required=True,
              type=click.Path(exists=True, dir_okay=False, readable=True, path_type=Path),
              help="Input PCAP capture to analyse.")
@click.option("--output", "output_path", required=False,
              type=click.Path(dir_okay=False, writable=True, path_type=Path),
              help="Write the report to this path. Format inferred from extension "
                   "(.html or .json); use --format to override.")
@click.option("--format", "fmt",
              type=click.Choice(["html", "json", "both"], case_sensitive=False),
              default=None,
              help="Output format. Defaults to inference from --output extension, "
                   "or to 'html' if neither is given.")
@click.option("--detector", "selected", multiple=True,
              type=click.Choice(sorted(ALL_DETECTORS.keys())),
              help="Restrict to one or more detectors (repeatable). Default: all.")
@click.option("--severity-threshold",
              type=click.Choice(SEVERITY_ORDER, case_sensitive=False),
              default="info", show_default=True,
              help="Suppress findings below this severity.")
@click.option("--print-summary/--no-print-summary", default=True,
              show_default=True, help="Echo the summary to stdout.")
def main(pcap_path: Path,
         output_path: Path | None,
         fmt: str | None,
         selected: tuple[str, ...],
         severity_threshold: str,
         print_summary: bool) -> None:
    """Read a Meshtastic PCAP and emit a security audit report."""
    frames = parse_pcap(pcap_path)

    detectors = ALL_DETECTORS if not selected else {
        name: ALL_DETECTORS[name] for name in selected
    }

    findings: list[Finding] = []
    for name, detect in detectors.items():
        findings.extend(detect(frames))

    # Apply severity threshold.
    min_rank = _SEVERITY_RANK[severity_threshold.lower()]
    findings = [f for f in findings if _SEVERITY_RANK[f.severity] >= min_rank]

    # Resolve format.
    if fmt is None:
        if output_path is not None and output_path.suffix.lower() == ".json":
            fmt = "json"
        else:
            fmt = "html"

    pcap_str = str(pcap_path)

    if fmt in ("html", "both"):
        html = to_html(findings, pcap_path=pcap_str)
        target = output_path if (output_path and fmt == "html") else (
            output_path.with_suffix(".html") if output_path else None
        )
        if target is None:
            click.echo(html)
        else:
            target.write_text(html, encoding="utf-8")
            click.echo(f"wrote {target}")

    if fmt in ("json", "both"):
        js = to_json(findings, pcap_path=pcap_str)
        target = output_path if (output_path and fmt == "json") else (
            output_path.with_suffix(".json") if output_path else None
        )
        if target is None:
            click.echo(js)
        else:
            target.write_text(js, encoding="utf-8")
            click.echo(f"wrote {target}")

    if print_summary:
        counts = {s: 0 for s in SEVERITY_ORDER}
        for f in findings:
            counts[f.severity] = counts.get(f.severity, 0) + 1
        line = " · ".join(f"{s}={counts[s]}" for s in SEVERITY_ORDER if counts[s])
        click.echo(f"summary: {len(findings)} finding(s) — {line or 'no findings'}",
                   err=True)


if __name__ == "__main__":
    main()
