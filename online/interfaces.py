"""
online/interfaces.py — XTI-SOC Phase 1

List available network interfaces and select a default.

Uses scapy.all.conf.ifaces which works on Windows (NPF GUIDs) and Linux (eth0 etc.).
The interface "name" returned here is what Scapy expects for sniff(iface=...).
"""

from scapy.all import conf


def get_interfaces() -> list[dict]:
    """
    Return a list of available network interfaces.

    Each entry is a dict:
      {
        "name":    str  — Scapy/NPF name used for sniff(iface=name)
        "ip":      str  — IPv4 address if available, else ""
        "display": str  — Human-readable label for terminal UI
      }

    On Windows, "name" is the NPF GUID like \\Device\\NPF_{...}.
    On Linux,   "name" is the OS name like "eth0".
    """
    result: list[dict] = []

    try:
        iface_dict = conf.ifaces
    except Exception:
        return result

    for network_name, iface in iface_dict.items():
        # Extract IPv4 address
        try:
            ip: str = iface.ip or ""
        except AttributeError:
            ip = ""

        # Extract human-readable description
        try:
            description: str = iface.description or iface.name or network_name
        except AttributeError:
            try:
                description = iface.name or network_name
            except AttributeError:
                description = str(network_name)

        # Build display string
        if description and ip:
            display = f"{description} ({ip})"
        elif description:
            display = description
        else:
            display = str(network_name)

        result.append({
            "name":    network_name,
            "ip":      ip,
            "display": display,
        })

    return result


def get_default_interface() -> str:
    """
    Return the Scapy name of the default interface (best guess).

    Tries conf.iface first (Scapy's own default).
    Falls back to the first interface in the list.
    Returns "" if no interfaces are found.
    """
    try:
        default = conf.iface
        # conf.iface may be an object or a string depending on Scapy version
        if hasattr(default, "network_name"):
            return default.network_name
        if hasattr(default, "name"):
            return default.name
        return str(default)
    except Exception:
        pass

    ifaces = get_interfaces()
    return ifaces[0]["name"] if ifaces else ""


def resolve_interface_name(name: str) -> str:
    """
    Given a friendly name like 'Wi-Fi' or 'Ethernet', returns the NPF GUID required
    by nfstream on Windows (e.g. \\Device\\NPF_{...}).
    If the name is already a valid GUID or Linux interface, it is returned as-is.
    """
    if not name:
        return ""

    # Already an NPF GUID or Linux typical interface
    if name.startswith("\\Device\\NPF_") or name.startswith("eth") or name.startswith("wlan"):
        return name

    ifaces = get_interfaces()
    name_lower = name.lower()

    # 1. Check against the display strings from get_interfaces()
    for iface in ifaces:
        display_lower = iface["display"].lower()
        clean_display = display_lower.split(" (")[0].strip()
        if name_lower == clean_display or name_lower in clean_display:
            return iface["name"]

    # 2. Check raw scapy interfaces for Windows "friendly" names
    try:
        from scapy.all import conf
        for network_name, iface in conf.ifaces.items():
            friendly = getattr(iface, "name", "").lower()
            if friendly == name_lower:
                return network_name
    except Exception:
        pass

    # Fallback to the original name if not found
    return name
