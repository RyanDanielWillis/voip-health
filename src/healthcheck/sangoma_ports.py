"""Sangoma Business Voice port catalog.

Source: https://sangomakb.atlassian.net/wiki/spaces/SBVS/pages/47153794/Business+Voice+-+Ports

The data is split into:

* ``PORT_CATALOG`` — every entry from the published guide, grouped by
  service. ``ports`` describes the published port range; ``sample_ports``
  is the small representative subset the scanner actually probes (full
  ranges like RTP 10000-65000 are intentionally NOT scanned end-to-end).
* ``SANGOMA_DEST_NETS`` — destination CIDRs the guide explicitly calls
  out. Used to pick representative IPs when the operator hasn't supplied
  one and to label whether a check targeted a Sangoma asset.

Edit this file by hand to change which ports are probed, add new
services, or switch sample IPs. Each entry is plain data so future
upload of the report into the VPS database can rely on the structure.
"""

from __future__ import annotations

from dataclasses import dataclass, field
from typing import Iterable


# Sangoma destination ranges named in the port guide. Keep small — the
# scanner picks ONE representative IP per range to avoid abusive volume.
SANGOMA_DEST_NETS = [
    "199.15.180.0/22",
]

# A representative IP inside 199.15.180.0/22 (network address + 1). The
# scanner probes this when the operator hasn't supplied a Sangoma host.
# Picking a single, stable IP keeps results comparable across runs.
DEFAULT_SANGOMA_HOST = "199.15.180.1"


@dataclass
class PortRule:
    """One row from the published port guide."""

    service: str            # e.g. "SIP", "RTP", "HTTPS"
    protocol: str           # "tcp" or "udp"
    ports: str              # raw range as published, e.g. "10000-65000"
    sample_ports: list[int]  # what we actually probe
    direction: str          # "IP Phones to Internet" / "Workstations to Internet"
    sip_alg_relevant: bool  # "SIP ALG" column from the guide
    destinations: list[str] = field(default_factory=list)
    notes: str = ""

    def as_dict(self) -> dict:
        return {
            "service": self.service,
            "protocol": self.protocol,
            "ports": self.ports,
            "sample_ports": list(self.sample_ports),
            "direction": self.direction,
            "sip_alg_relevant": self.sip_alg_relevant,
            "destinations": list(self.destinations),
            "notes": self.notes,
        }


@dataclass
class PortGroup:
    """A logical group from the guide (e.g. Core Voice Services)."""

    name: str
    rules: list[PortRule]

    def as_dict(self) -> dict:
        return {
            "name": self.name,
            "rules": [r.as_dict() for r in self.rules],
        }


# -- Catalog ---------------------------------------------------------------
# Each "ports" string mirrors the published guide; "sample_ports" is the
# subset the scanner actually probes. Edit sample_ports to broaden /
# narrow coverage. Keep total probes small for politeness and speed.

PORT_CATALOG: list[PortGroup] = [
    PortGroup(
        name="Core Voice Services",
        rules=[
            PortRule(
                service="SIP",
                protocol="tcp",
                ports="2160",
                sample_ports=[2160],
                direction="IP Phones to Internet",
                sip_alg_relevant=True,
                destinations=list(SANGOMA_DEST_NETS),
                notes="Sangoma SIP signaling on TCP 2160.",
            ),
            PortRule(
                service="SIP",
                protocol="udp",
                ports="2160",
                sample_ports=[2160],
                direction="IP Phones to Internet",
                sip_alg_relevant=True,
                destinations=list(SANGOMA_DEST_NETS),
                notes="Sangoma SIP signaling on UDP 2160.",
            ),
            PortRule(
                service="RTP",
                protocol="udp",
                ports="10000-65000",
                # Sample at the bottom, middle and top of the range.
                # Full-range UDP scanning is intentionally avoided.
                sample_ports=[10000, 10001, 20000, 30000, 40000, 50000, 60000, 65000],
                direction="IP Phones to Internet",
                sip_alg_relevant=True,
                destinations=list(SANGOMA_DEST_NETS),
                notes="Voice media RTP. Massive UDP range; scanner samples it.",
            ),
            PortRule(
                service="NTP",
                protocol="tcp",
                ports="123",
                sample_ports=[123],
                direction="IP Phones to Internet",
                sip_alg_relevant=False,
                destinations=[],
                notes="Phone time sync (TCP 123 per the guide).",
            ),
        ],
    ),
    PortGroup(
        name="Application Framework",
        rules=[
            PortRule(
                service="HTTPS",
                protocol="tcp",
                ports="443",
                sample_ports=[443],
                direction="Workstations to Internet",
                sip_alg_relevant=False,
                destinations=[],
                notes="Generic outbound HTTPS.",
            ),
            PortRule(
                service="HTTP",
                protocol="tcp",
                ports="80",
                sample_ports=[80],
                direction="Workstations to Internet",
                sip_alg_relevant=False,
                destinations=[],
                notes="Generic outbound HTTP.",
            ),
            PortRule(
                service="XMPP",
                protocol="tcp",
                ports="5280-5281",
                sample_ports=[5280, 5281],
                direction="Workstations to Internet",
                sip_alg_relevant=True,
                destinations=[],
                notes="Application Framework XMPP.",
            ),
            PortRule(
                service="StarFax Personal",
                protocol="tcp",
                ports="9080",
                sample_ports=[9080],
                direction="Workstations to Internet",
                sip_alg_relevant=True,
                destinations=[],
            ),
            PortRule(
                service="Application Framework Video",
                protocol="tcp",
                ports="1935",
                sample_ports=[1935],
                direction="Workstations to Internet",
                sip_alg_relevant=False,
                destinations=[],
            ),
        ],
    ),
    PortGroup(
        name="StarPhone Desktop v3.x",
        rules=[
            PortRule(
                service="SIP",
                protocol="tcp",
                ports="59000-60000",
                sample_ports=[59000, 59500, 60000],
                direction="Workstations to Internet",
                sip_alg_relevant=True,
                destinations=[],
                notes="StarPhone desktop SIP register/signal.",
            ),
            PortRule(
                service="RTC",
                protocol="udp",
                ports="10000-20000",
                sample_ports=[10000, 12500, 15000, 17500, 20000],
                direction="Workstations to Internet",
                sip_alg_relevant=True,
                destinations=[],
                notes="StarPhone desktop media.",
            ),
            PortRule(
                service="HTTPS",
                protocol="tcp",
                ports="443",
                sample_ports=[443],
                direction="Workstations to Internet",
                sip_alg_relevant=True,
                destinations=[],
            ),
            PortRule(
                service="HTTP",
                protocol="tcp",
                ports="80",
                sample_ports=[80],
                direction="Workstations to Internet",
                sip_alg_relevant=True,
                destinations=[],
            ),
        ],
    ),
    PortGroup(
        name="StarPhone iPhone / Android / TeamHub",
        rules=[
            PortRule(
                service="SIP",
                protocol="tcp",
                ports="5060,2160",
                sample_ports=[5060, 2160],
                direction="Workstations to Internet",
                sip_alg_relevant=True,
                destinations=list(SANGOMA_DEST_NETS),
            ),
            PortRule(
                service="XMPP",
                protocol="tcp",
                ports="5222",
                sample_ports=[5222],
                direction="Workstations to Internet",
                sip_alg_relevant=True,
                destinations=list(SANGOMA_DEST_NETS),
            ),
            PortRule(
                service="HTTPS",
                protocol="tcp",
                ports="443",
                sample_ports=[443],
                direction="Workstations to Internet",
                sip_alg_relevant=True,
                destinations=[],
            ),
            PortRule(
                service="HTTP",
                protocol="tcp",
                ports="80",
                sample_ports=[80],
                direction="Workstations to Internet",
                sip_alg_relevant=True,
                destinations=[],
            ),
            PortRule(
                service="RTP/RTCP",
                protocol="udp",
                ports="4000-4007,10000-40000",
                sample_ports=[4000, 4001, 4007, 10000, 20000, 30000, 40000],
                direction="Workstations to Internet",
                sip_alg_relevant=True,
                destinations=list(SANGOMA_DEST_NETS),
                notes=(
                    "Mobile media — guide notes 4000-4007 and/or "
                    "10000-40000 (or up to 65000) to 199.15.180.0/22."
                ),
            ),
        ],
    ),
]


def all_rules() -> Iterable[PortRule]:
    for group in PORT_CATALOG:
        yield from group.rules


def catalog_as_dict() -> dict:
    """Plain-dict representation suitable for JSON / VPS upload."""
    return {
        "destination_networks": list(SANGOMA_DEST_NETS),
        "default_sangoma_host": DEFAULT_SANGOMA_HOST,
        "groups": [g.as_dict() for g in PORT_CATALOG],
    }
