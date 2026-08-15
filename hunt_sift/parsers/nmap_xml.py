"""Parser for pre-exported local Nmap XML files. It never invokes Nmap."""

from __future__ import annotations

import xml.etree.ElementTree as ET
from pathlib import Path

from ..core.io import read_text
from ..core.models import Lead


def analyze(path: Path) -> list[Lead]:
    """Generate inventory and configuration-review leads from imported Nmap XML."""
    try:
        root = ET.fromstring(read_text(path))
    except ET.ParseError as exc:
        raise ValueError(f"Invalid Nmap XML: {exc}") from exc

    leads: list[Lead] = []
    legacy_services = {"telnet", "ftp", "rsh", "rlogin", "rexec"}
    for host in root.findall("host"):
        address = host.find("address")
        host_label = address.get("addr", "unknown-host") if address is not None else "unknown-host"
        for port in host.findall("./ports/port"):
            state = port.find("state")
            if state is None or state.get("state") != "open":
                continue
            service = port.find("service")
            port_id = port.get("portid", "?")
            protocol = port.get("protocol", "tcp")
            service_name = (service.get("name", "unknown") if service is not None else "unknown").lower()
            product = service.get("product", "") if service is not None else ""
            version = service.get("version", "") if service is not None else ""
            evidence = f"{host_label} {protocol}/{port_id} reports service '{service_name}'"
            if service_name in legacy_services:
                leads.append(Lead("nmap-xml", "legacy-service-review", "review", f"Imported scan lists an open {service_name} service.", evidence, "Confirm scope and ownership, then review whether this service is expected, access-controlled, and still required. Do not infer a vulnerability from service presence alone."))
            if service_name == "http":
                leads.append(Lead("nmap-xml", "transport-review", "review", "Imported scan lists HTTP. Compare the service inventory and transport policy with the authorized program requirements.", evidence, "Review redirect behavior and any HTTPS companion service only within confirmed scope; Hunt Sift does not make network requests."))
            if product or version:
                fingerprint = " ".join(part for part in (product, version) if part)
                leads.append(Lead("nmap-xml", "service-inventory", "informational", "Imported scan contains service-version metadata.", f"{evidence}; fingerprint: {fingerprint}", "Treat version output as an inventory clue. Validate it against an authorized asset inventory before making any security conclusion."))
    return leads
