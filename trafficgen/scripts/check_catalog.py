#!/usr/bin/env python3
"""Gap check: every expected protocol has template + craft hooks."""
from __future__ import annotations

import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT))

from app.registry import all_protocols, expected_ids, templates_by_category  # noqa: E402


def main() -> int:
    expected = set(expected_ids())
    registered = {p.id: p for p in all_protocols()}
    missing = sorted(expected - set(registered))
    extra_expected_ok = True

    errors: list[str] = []
    if missing:
        errors.append(f"missing registry entries: {missing}")

    # Every registered protocol must be craftable and have template meta
    for pid, p in sorted(registered.items()):
        if not p.craftable:
            errors.append(f"{pid}: craftable is False")
        if not p.template or not p.template.blurb:
            errors.append(f"{pid}: missing template blurb")
        if not p.fields and pid != "pcap_replay":
            # pcap can have optional fields only — still has fields
            pass
        if p.build is None:
            errors.append(f"{pid}: missing build()")

    # Templates gallery must surface every protocol
    in_gallery = set()
    for cat, items in templates_by_category().items():
        for p in items:
            in_gallery.add(p["id"])
    not_in_gallery = sorted(set(registered) - in_gallery)
    if not_in_gallery:
        errors.append(f"not in templates gallery: {not_in_gallery}")

    # Expected catalog from plan should all be present
    plan_min = expected
    if plan_min - set(registered):
        errors.append(f"plan catalog gaps: {sorted(plan_min - set(registered))}")

    print(f"registered={len(registered)} expected={len(expected)}")
    if errors:
        print("FAIL")
        for e in errors:
            print(" -", e)
        return 1
    print("OK: every protocol has template + craft")
    # Smoke-build a few
    from app.builder import build_from_protocol

    smoke = [
        "udp",
        "dot1q",
        "ospfv2",
        "vxlan",
        "vc_juniper",
        "raw_l2",
        "bum_spam",
        "uuf",
        "rocev2",
        "srv6",
        "modbus_tcp",
        "ikev2",
    ]
    for sid in smoke:
        try:
            pkt = build_from_protocol(sid, {})
            assert pkt is not None
            print(f"  build {sid}: {pkt.summary()}")
        except Exception as e:
            print(f"FAIL smoke {sid}: {e}")
            return 1
    # BUM must vary dst MAC across builds
    dsts = {bytes(build_from_protocol("bum_spam", {}))[0:6] for _ in range(24)}
    if len(dsts) < 3:
        print(f"FAIL bum_spam dst diversity: only {len(dsts)} unique dst MACs in 24 builds")
        return 1
    print(f"  bum_spam dst diversity: {len(dsts)} unique in 24 builds")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
