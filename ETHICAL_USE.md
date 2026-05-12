# Ethical Use Policy

`meshtastic-security-audit` is a passive analysis toolkit. It reads
PCAP files and produces a report. It does not transmit, inject,
spoof, or otherwise interact with a live mesh network.

## Permitted use

- Auditing a mesh network you own or have written authorisation to
  assess.
- Reviewing your own captures during product development or
  certification.
- Academic and research analysis of public Meshtastic captures
  (operator's own field tests, published datasets, conference CTF
  artefacts, etc.).
- Security training and CTF environments.

## Prohibited use

- Capturing or analysing traffic from a mesh you do not operate and
  have not been authorised to assess.
- Targeting individuals: tracking specific node identifiers,
  correlating GPS positions, or compiling identity-linkable patterns
  of life from observed traffic.
- Using GPS extraction or node enumeration findings to physically
  locate, harass, or surveil another operator.
- Any activity that violates the radio-spectrum, computer-misuse,
  or data-protection regulations of the operator's jurisdiction.

## Operator responsibilities

Before running the toolkit against a capture you did not produce
yourself in an authorised context:

1. Confirm written authorisation for the underlying capture activity.
   In many jurisdictions, intercepting and decoding radio traffic
   not intended for you is regulated separately from network
   security analysis.
2. Minimise data retention. Findings should be retained only as long
   as the engagement requires; the raw PCAP should be wiped at
   engagement close.
3. Report findings through the appropriate disclosure channel — to
   the operator of the mesh, the manufacturer, or a relevant CERT —
   rather than publishing identifiable detail.

## Attribution

This toolkit depends on and credits:

- The Meshtastic project — https://meshtastic.org — protocol
  specification and protobuf definitions.
- Scapy — https://scapy.net — Python packet manipulation library.
- The Click project — https://click.palletsprojects.com — CLI
  framework.

These dependencies carry their own licences; this repository's MIT
licence governs only the audit toolkit code, tests, and
documentation.
