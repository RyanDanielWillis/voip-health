"""VLAN 41 evidence on the current Windows connection.

Why this is hard from a Windows client:

* Most Windows NIC drivers strip 802.1Q tags before the OS sees them.
* On an *access* port the switch already strips the tag.
* On a *trunk* port the NIC can be configured to expose the tag via
  the adapter's advanced properties or a vendor virtual interface
  (Intel/Broadcom/Realtek dialogs differ).

So we gather every signal we can — adapter VLAN ID exposed by Windows,
adapter advanced "VLAN ID" registry hint, IP subnet hint (a 10.41.x.x
or 192.168.41.x address strongly suggests a voice VLAN even if tagging
isn't visible), and the operator-supplied gateway hint — and combine
them into a confidence-aware verdict.
"""

from __future__ import annotations

import ipaddress
import re
from typing import Iterable

from . import paths
from .netinfo import _powershell
from .report import NetworkInterface, VlanEvidence


TARGET_VLAN = 41


def _ipv4_in(net: str, ip: str) -> bool:
    try:
        return ipaddress.ip_address(ip) in ipaddress.ip_network(net)
    except Exception:
        return False


def _adapter_advanced_vlan_ids() -> list[tuple[str, int]]:
    """Read Windows NDI VlanID advanced-property values (if any).

    Returns a list of ``(adapter_name, vlan_id)`` tuples. NIC drivers
    expose this differently; we read the standard ``Get-NetAdapterAdvancedProperty``
    keyed by 'VlanID'.
    """
    if not paths.is_windows():
        return []
    snippet = (
        "Get-NetAdapterAdvancedProperty -ErrorAction SilentlyContinue "
        "| Where-Object { $_.RegistryKeyword -match 'VlanID' -or $_.DisplayName -match 'VLAN' } "
        "| ForEach-Object { '{0}|{1}|{2}' -f $_.Name, $_.RegistryKeyword, $_.RegistryValue }"
    )
    rc, out, _ = _powershell(snippet, timeout=10)
    if rc != 0:
        return []
    parsed: list[tuple[str, int]] = []
    for line in out.splitlines():
        parts = line.split("|")
        if len(parts) >= 3:
            name = parts[0].strip()
            val = parts[2].strip().strip("{}").split()[0] if parts[2].strip() else ""
            try:
                vid = int(val)
                if vid >= 0:
                    parsed.append((name, vid))
            except Exception:
                continue
    return parsed


def _subnet_signals_voice_vlan(ipv4: str) -> bool:
    """Heuristic: addresses commonly assigned to a voice/41 VLAN."""
    if not ipv4:
        return False
    return any(
        _ipv4_in(net, ipv4)
        for net in (
            "10.41.0.0/16",
            "192.168.41.0/24",
            "172.16.41.0/24",
        )
    )


def assess_vlan(
    interfaces: Iterable[NetworkInterface],
    *,
    user_gateway: str = "",
) -> VlanEvidence:
    nics = list(interfaces)
    evidence: list[str] = []
    suggestions: list[str] = []

    direct_tag = False
    subnet_hit = False
    advanced_match = False

    for nic in nics:
        if nic.vlan_id == TARGET_VLAN:
            direct_tag = True
            evidence.append(
                f"Adapter '{nic.name}' reports VLAN ID {TARGET_VLAN} "
                f"directly via Get-NetAdapter."
            )
        for ip in nic.ipv4:
            if _subnet_signals_voice_vlan(ip):
                subnet_hit = True
                evidence.append(
                    f"Adapter '{nic.name}' has IPv4 {ip} — subnet name "
                    f"contains '41', strong hint of a voice/41 VLAN."
                )

    for name, vid in _adapter_advanced_vlan_ids():
        if vid == TARGET_VLAN:
            advanced_match = True
            evidence.append(
                f"NIC advanced property exposes VLAN ID {TARGET_VLAN} on '{name}'."
            )

    if user_gateway and any(
        user_gateway.startswith(p)
        for p in ("10.41.", "192.168.41.", "172.16.41.")
    ):
        evidence.append(
            f"Operator-supplied gateway {user_gateway} sits in a 41-style "
            "voice subnet — reinforces VLAN-41 hypothesis."
        )
        subnet_hit = True

    # Combine
    if direct_tag or advanced_match:
        status = "confirmed"
        confidence = "confirmed"
    elif subnet_hit:
        status = "inconclusive"
        confidence = "likely"
        evidence.append(
            "Subnet hint alone is not proof of 802.1Q tagging — "
            "an unmanaged port can carry these IPs untagged."
        )
    else:
        status = "not_detected"
        confidence = "inconclusive"
        evidence.append(
            "No Windows-visible VLAN tag and no 41-style subnet detected. "
            "If the switch port is an access port, Windows cannot see the "
            "tag even when one is in use."
        )

    explanation = (
        "Windows commonly cannot observe 802.1Q tags unless the NIC driver "
        "is explicitly configured to expose VLAN IDs or the switch port is "
        "a trunk. Treat 'not_detected' as 'we couldn't see it', not 'it isn't there'."
    )
    suggestions.extend([
        "On the switch, confirm the port is configured for VLAN 41 "
        "(access mode for a phone, trunk with native data + tagged voice "
        "for a PC + phone in line).",
        "If using a phone with a passthrough PC port, verify the phone "
        "is tagging voice on VLAN 41 and leaving PC traffic untagged.",
        "On the Windows NIC, check Device Manager -> Adapter -> Advanced "
        "for a 'VLAN ID' or 'Priority & VLAN' setting.",
    ])

    return VlanEvidence(
        target_vlan=TARGET_VLAN,
        status=status,
        confidence=confidence,
        evidence=evidence,
        explanation=explanation,
        suggestions=suggestions,
    )
