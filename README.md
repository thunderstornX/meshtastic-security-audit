<!-- markdownlint-disable MD033 MD041 -->

```
 ┌──────────────────────────────────────────────────────────────┐
 │   m e s h t a s t i c - s e c u r i t y - a u d i t          │
 │                                                              │
 │   passive PCAP audit · 4 detectors · HTML + JSON reports     │
 └──────────────────────────────────────────────────────────────┘
```

[![pytest](https://img.shields.io/badge/pytest-23%2F23-brightgreen)](#testing)
[![bandit](https://img.shields.io/badge/bandit-0%20issues-brightgreen)](results/security_scan.md)
[![pip-audit](https://img.shields.io/badge/pip--audit-0%20vulns-brightgreen)](results/security_scan.md)
[![semgrep](https://img.shields.io/badge/semgrep-exit%200-brightgreen)](results/security_scan.md)
[![eval F1](https://img.shields.io/badge/eval%20F1-1.000-brightgreen)](results/eval_summary.json)
[![DOI](https://zenodo.org/badge/DOI/10.5281/zenodo.20480462.svg)](https://doi.org/10.5281/zenodo.20480462)
[![License: MIT](https://img.shields.io/badge/license-MIT-blue)](LICENSE)

Passive analysis of Meshtastic packet captures. The toolkit reads a
PCAP, parses the Meshtastic frame structure on the LoRa link layer,
and reports four classes of finding:

- **Default channel** — frames whose channel hash matches one of the
  seven documented Meshtastic modem presets under the default
  one-byte PSK index.
- **Node enumeration** — distinct source and destination node ids
  observed in the capture, surfaced as an inventory with per-source
  frame counts.
- **Unencrypted traffic** — frames with the encrypted-bit clear, or
  whose payload bytes decode as a plaintext Meshtastic `Data`
  protobuf.
- **GPS leakage** — recoverable latitude/longitude pairs in
  unencrypted position payloads.

Reports are emitted as inline-styled HTML or canonical JSON.

> Read [ETHICAL_USE.md](ETHICAL_USE.md) before running this toolkit
> against any capture you did not produce yourself in an authorised
> context.

## Architecture

```
                ┌─ pcap_parser.py ─┐
   capture.pcap │  Scapy + custom  │  list[MeshFrame]
   ────────────►│   header decode  ├──────┐
                └──────────────────┘      │
                                          ▼
                          ┌───────────────────────────┐
                          │   detectors/              │
                          │    default_key.py         │
                          │    node_enum.py           │   list[Finding]
                          │    unencrypted.py         ├──────┐
                          │    gps_leak.py            │      │
                          └───────────────────────────┘      │
                                                             ▼
                                              ┌────────────────────────┐
                                              │  reporter.py           │
                                              │   to_html / to_json    │
                                              └─────────┬──────────────┘
                                                        │
                                                        ▼
                                              report.html / report.json
```

## Quick start

```bash
git clone https://github.com/thunderstornX/meshtastic-security-audit.git
cd meshtastic-security-audit

python -m venv .venv
.venv/bin/pip install -r requirements.txt

# Run the audit against the bundled synthetic capture
.venv/bin/python cli.py \
    --pcap samples/sample.pcap \
    --output report.html

# Or emit JSON alongside HTML
.venv/bin/python cli.py \
    --pcap samples/sample.pcap \
    --output report \
    --format both
```

The CLI accepts:

| Flag | Effect |
|---|---|
| `--pcap PATH`              | Input capture (required). |
| `--output PATH`            | Where to write the report. Extension drives format unless `--format` is given. |
| `--format html\|json\|both` | Output format override. |
| `--detector NAME`          | Restrict to one detector. Repeatable. |
| `--severity-threshold S`   | Suppress findings below severity `S` (info → critical). |
| `--print-summary`          | Echo a one-line summary to stderr (default on). |

## Detectors

### `default_key` — severity `high`

Computes the channel hash that would result for every documented
Meshtastic preset name (`LongFast`, `LongSlow`, `VeryLongSlow`,
`MediumSlow`, `MediumFast`, `ShortSlow`, `ShortFast`) under the
default 1-byte PSK index of `0x01`, and flags any frame whose channel
byte matches. Anyone with a Meshtastic node running the same preset
out of the box can decode traffic carrying these hashes.

### `node_enum` — severity `info` + `medium`

Counts distinct source ids (every frame exposes one) and unicast
destinations. The two summary findings answer "how many nodes are
visible from this vantage" and "how many of them are talking to each
other directly".

### `unencrypted` — severity `high` + `critical`

Two complementary signals: the encrypted bit (0x10) being clear in
the flags byte (high), and a payload whose first bytes parse as a
plaintext `Data` protobuf with the field-1 tag and printable inner
bytes (critical). The second signal is content-based and reproduces
even on traffic where the encrypted flag was set incorrectly.

### `gps_leak` — severity `critical`

Decodes any `Data` envelope on port 3 (`POSITION_APP`) and extracts
`latitude_i` and `longitude_i` (int32 scaled by 1e7). Each recovered
lat/lon pair is sufficient to place the broadcasting node on a map.
The detector does not attempt decryption; encrypted position frames
produce no finding.

## Eval

The toolkit is shipped with a synthetic, byte-level labelled corpus
in `tests/fixtures/test_packets.py` (5 frames covering all four
detector signals). The harness in `eval/run_eval.py` reads the
ground-truth labels from `eval/labelled_corpus.json` and produces:

| Detector       | TP | FP | FN | P     | R     | F₁    |
|----------------|---:|---:|---:|------:|------:|------:|
| `default_key`  |  1 |  0 |  0 | 1.000 | 1.000 | 1.000 |
| `node_enum`    |  5 |  0 |  0 | 1.000 | 1.000 | 1.000 |
| `unencrypted`  |  2 |  0 |  0 | 1.000 | 1.000 | 1.000 |
| `gps_leak`     |  1 |  0 |  0 | 1.000 | 1.000 | 1.000 |
| **Aggregate**  |  9 |  0 |  0 | 1.000 | 1.000 | 1.000 |

Regenerate with `.venv/bin/python eval/run_eval.py` — writes
`results/eval_summary.json` and `results/eval_raw.csv`.

The synthetic corpus exists because there is no public Meshtastic
PCAP dataset of comparable scale; the labels are tied to the frame
constructors in `tests/fixtures/test_packets.py`. For a real-mesh
audit, capture your own traffic and run the same CLI against it.

## Testing

```bash
.venv/bin/pytest -q
```

| Module               | Tests |
|----------------------|------:|
| `test_pcap_parser.py` |  7 |
| `test_detectors.py`   |  8 |
| `test_reporter.py`    |  4 |
| `test_cli.py`         |  4 |
| **Total**             | **23** |

## Security gates

| Gate | Findings |
|---|---|
| Bandit (medium+)            | 0 |
| pip-audit                   | 0 |
| Semgrep (p/python, p/security-audit) | exit 0 |

Run output is in [`results/security_scan.md`](results/security_scan.md).

## Capturing real Meshtastic traffic

The toolkit consumes whatever your capture pipeline puts into a PCAP.
Two paths in common use:

- **SDR + LoRa decoder.** An RTL-SDR or HackRF tuned to the regional
  ISM band (433 / 868 / 915 MHz) feeding `gr-lora_sdr` or
  `LoRaWatcher`, with the decoded frames serialised as raw bytes per
  packet.
- **Firmware debug serial sniffer.** The `meshtastic` Python client
  exposes a frame-level debug stream over USB serial; that stream
  can be serialised by hand into PCAP records.

The toolkit deliberately leaves the capture step to the operator;
RF capture has its own regulatory implications that vary by
jurisdiction.

## Repository layout

```
meshtastic-security-audit/
├── audit/
│   ├── pcap_parser.py           # Scapy-backed frame parser
│   ├── reporter.py              # HTML + JSON output
│   └── detectors/
│       ├── default_key.py
│       ├── node_enum.py
│       ├── unencrypted.py
│       └── gps_leak.py
├── cli.py                       # Click CLI
├── config.py                    # Preset constants + hash function
├── eval/
│   ├── labelled_corpus.json
│   └── run_eval.py
├── tests/
│   ├── test_pcap_parser.py
│   ├── test_detectors.py
│   ├── test_reporter.py
│   ├── test_cli.py
│   └── fixtures/test_packets.py
├── samples/
│   ├── README.md
│   └── sample.pcap              # 5 synthetic frames
├── paper/                       # 3-page IEEE writeup
├── results/                     # eval + security scan outputs
└── ETHICAL_USE.md
```

## License

MIT. See [LICENSE](LICENSE). The toolkit depends on the
[Meshtastic project](https://meshtastic.org) for protocol definitions
and on [Scapy](https://scapy.net) for packet manipulation; both
carry their own licences.
