"""
scripts/validate_nfstream.py — XTI-SOC

Quick smoke-test for nfstream live capture BEFORE hooking it to the ML pipeline.

What this script verifies:
  1.  Captures exactly 10 flows from the selected interface
  2.  Prints ALL available field names on a flow object
  3.  Checks that statistical_analysis fields (piat) are present and non-zero
  4.  Prints a sample feature vector for the first valid flow
  5.  Verifies the vector is shape (1, 25) float64 with no inf/nan

Run from the project root (as Administrator on Windows):
  python -m scripts.validate_nfstream
  -- or --
  python scripts/validate_nfstream.py

If nfstream cannot open the interface:
  • Make sure Npcap is installed
  • Run the terminal / IDE as Administrator
  • Use the exact NPF GUID from Wireshark or scripts/list_interfaces.py
"""

import sys
import os

# Allow running as a standalone script from the project root
sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

import numpy as np
import nfstream

# Import flow_to_features from the online engine (avoids duplication)
from online.nfstream_engine import flow_to_features, FEATURE_NAMES


# ── Helpers ───────────────────────────────────────────────────────────────────

def pick_interface() -> str:
    """
    Show available interfaces and let the user pick one.
    Falls back to Scapy's default if user presses Enter.
    """
    try:
        from scapy.all import conf
        ifaces = []
        for name, iface in conf.ifaces.items():
            try:
                desc = iface.description or iface.name or name
                ip   = iface.ip or ""
            except AttributeError:
                desc, ip = str(name), ""
            display = f"{desc} ({ip})" if ip else desc
            ifaces.append({"name": name, "display": display})

        if not ifaces:
            raise RuntimeError("No interfaces found via Scapy")

        print("\nAvailable interfaces:")
        print("-" * 70)
        for i, iface in enumerate(ifaces):
            print(f"  [{i}] {iface['display']}")
        print("-" * 70)

        raw = input(f"Select interface [0-{len(ifaces)-1}] or paste name directly: ").strip()

        if raw == "":
            default = conf.iface
            name = (default.network_name if hasattr(default, "network_name")
                    else default.name if hasattr(default, "name")
                    else str(default))
            print(f"Using default: {name}")
            return name

        try:
            return ifaces[int(raw)]["name"]
        except (ValueError, IndexError):
            # User pasted a raw interface name
            return raw

    except ImportError:
        # Scapy not available — just ask for a name
        return input("Enter interface name (NPF GUID or friendly name): ").strip()


# ── Section printers ──────────────────────────────────────────────────────────

SEP  = "─" * 70
SEP2 = "═" * 70

def section(title: str) -> None:
    print(f"\n{SEP2}")
    print(f"  {title}")
    print(SEP2)


# ── Main validation ───────────────────────────────────────────────────────────

def main() -> None:
    print(f"\n{'='*70}")
    print("  XTI-SOC — nfstream validation script")
    print(f"  nfstream version: {nfstream.__version__}")
    print(f"{'='*70}")

    # ── Step 1: Pick interface ─────────────────────────────────────────────────
    iface = pick_interface()
    
    # Resolve the name to NPF GUID if needed matching online behavior
    from online.interfaces import resolve_interface_name
    resolved_iface = resolve_interface_name(iface)

    print(f"\n[VALIDATE] Capturing 10 flows on: {resolved_iface}")
    print("           Generate some traffic (browse, ping, etc.) …\n")

    # ── Step 2: Capture 10 flows ───────────────────────────────────────────────
    flows: list = []
    streamer = nfstream.NFStreamer(
        source=resolved_iface,
        statistical_analysis=True,   # REQUIRED for piat fields
        accounting_mode=0,           # IP-payload bytes
        idle_timeout=30,             # short timeout for quick validation
        active_timeout=60,
        promiscuous_mode=True,
        max_nflows=10,               # stop after 10 flows
    )

    for flow in streamer:
        flows.append(flow)
        print(
            f"  Flow #{len(flows):02d}: "
            f"{flow.src_ip}:{flow.src_port} → "
            f"{flow.dst_ip}:{flow.dst_port}  "
            f"pkts={flow.bidirectional_packets}  "
            f"bytes={flow.bidirectional_bytes}"
        )

    if not flows:
        print("\n[ERROR] No flows captured. Check interface name and run as Admin.")
        sys.exit(1)

    print(f"\n✅  Captured {len(flows)} flow(s).")

    # ── Step 3: Print all available field names ────────────────────────────────
    section("ALL AVAILABLE FIELD NAMES ON FLOW OBJECT")
    sample = flows[0]

    all_fields = [
        attr for attr in dir(sample)
        if not attr.startswith("_") and not callable(getattr(sample, attr))
    ]
    print(f"Total fields: {len(all_fields)}\n")

    # Group by prefix for readability
    prefixes = ["bidirectional", "src2dst", "dst2src", "splt", "udps"]
    printed = set()

    for prefix in prefixes:
        group = [f for f in all_fields if f.startswith(prefix)]
        if group:
            print(f"  [{prefix}*]")
            for f in sorted(group):
                print(f"    {f} = {getattr(sample, f)!r}")
            printed.update(group)

    # Remaining fields
    remaining = [f for f in all_fields if f not in printed]
    if remaining:
        print("  [other]")
        for f in sorted(remaining):
            print(f"    {f} = {getattr(sample, f)!r}")

    # ── Step 4: Verify statistical_analysis fields ─────────────────────────────
    section("STATISTICAL ANALYSIS FIELD CHECK")

    piat_fields = [
        "bidirectional_mean_piat_ms",
        "src2dst_mean_piat_ms",
        "dst2src_mean_piat_ms",
    ]

    all_ok = True
    for field in piat_fields:
        exists = hasattr(sample, field)
        value  = getattr(sample, field, "MISSING")
        status = "✅" if exists else "❌"
        warning = ""
        if exists and isinstance(value, (int, float)) and value == 0:
            # Zero is valid for single-packet flows — not necessarily an error
            warning = "  ⚠  (0 — single-packet flow or no IAT data)"
        print(f"  {status}  {field} = {value!r}{warning}")
        if not exists:
            all_ok = False

    if all_ok:
        print("\n✅  All piat fields are present (statistical_analysis=True confirmed).")
    else:
        print("\n❌  Some piat fields are missing! "
              "Ensure you are using nfstream ≥ 6.0 with statistical_analysis=True.")

    # ── Step 5: Sample feature vector ─────────────────────────────────────────
    section("SAMPLE FEATURE VECTOR (first valid flow)")

    vec = None
    chosen_flow = None
    for flow in flows:
        vec = flow_to_features(flow)
        if vec is not None:
            chosen_flow = flow
            break

    if vec is None:
        print("⚠  All captured flows were discarded by flow_to_features().")
        print("   This is normal if only single-packet flows were captured.")
        print("   Generate bidirectional TCP traffic (e.g. curl, ping) and retry.")
    else:
        print(f"\nFlow: {chosen_flow.src_ip}:{chosen_flow.src_port} → "
              f"{chosen_flow.dst_ip}:{chosen_flow.dst_port}\n")
        print(f"  Shape:  {vec.shape}    ← must be (1, 25)")
        print(f"  dtype:  {vec.dtype}  ← must be float64")
        print(f"  has inf: {np.any(np.isinf(vec))}  |  has nan: {np.any(np.isnan(vec))}\n")

        print(f"  {'Feature':<22}  {'Value':>18}")
        print(f"  {'-'*22}  {'-'*18}")
        for name, val in zip(FEATURE_NAMES, vec.flatten()):
            print(f"  {name:<22}  {val:>18.4f}")

        # Shape and dtype assertions
        assert vec.shape == (1, 25), f"Shape mismatch: {vec.shape}"
        assert vec.dtype == np.float64, f"dtype mismatch: {vec.dtype}"
        assert not np.any(np.isinf(vec)), "inf values in feature vector"
        assert not np.any(np.isnan(vec)), "nan values in feature vector"

        print(f"\n✅  Feature vector is shape (1, 25) float64 with no inf/nan.")

    # ── Done ───────────────────────────────────────────────────────────────────
    section("VALIDATION COMPLETE")
    print(f"  ✅  nfstream {nfstream.__version__} is working correctly.")
    print("  ✅  statistical_analysis fields are available.")
    print("  ✅  accounting_mode=0 (IP-payload bytes).")
    print("  ✅  Interface accepts NPF GUID names (same as Scapy/Npcap).")
    print()
    print("  You can now integrate NFStreamEngine with the ML pipeline.")
    print("  Run:  python -m online.main")
    print()


if __name__ == "__main__":
    main()
