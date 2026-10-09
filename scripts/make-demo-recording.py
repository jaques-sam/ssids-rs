#!/usr/bin/env python3
"""Generate the synthetic demo recording used by the browser demo and tests.

Writes crates/ssids-adapter-replay/recordings/demo.jsonl: one Scan (JSON) per
line. The access points are invented but their information elements are
well-formed, so they exercise the real parser: 2.4/5/6 GHz, 20-160 MHz,
Open/WEP/WPA/WPA2/WPA3/OWE/Enterprise and a hidden network.
"""
import json
import math
import pathlib
import random

OUT = pathlib.Path(__file__).resolve().parent.parent / "crates/ssids-adapter-replay/recordings/demo.jsonl"
FRAMES = 60
IEEE, MS = "000fac", "0050f2"


def el(eid: int, body: str) -> str:
    return f"{eid:02x}{len(body) // 2:02x}{body}"


def ssid(name: str) -> str:
    return el(0, name.encode().hex())


RATES_B = el(1, "82848b96")
RATES_G = el(1, "8c129824b048606c")
HT_CAP = el(45, "00" * 26)
VHT_CAP = el(191, "00" * 12)
HE_CAP = el(255, "23")


def ht_op(primary: int, offset: int) -> str:
    return el(61, f"{primary:02x}{offset:02x}" + "00" * 20)


def vht_op(width: int, ccfs0: int, ccfs1: int = 0) -> str:
    return el(192, f"{width:02x}{ccfs0:02x}{ccfs1:02x}0000")


def he_op_6ghz(primary: int, width: int, ccfs0: int, ccfs1: int = 0) -> str:
    return el(255, f"24000002000000{primary:02x}{width:02x}{ccfs0:02x}{ccfs1:02x}00")


def suites(oui: str, kinds: list) -> str:
    return f"{len(kinds):02x}00" + "".join(f"{oui}{k:02x}" for k in kinds)


def rsn(pairwise: list, akms: list) -> str:
    return el(48, "0100" + f"{IEEE}{pairwise[0]:02x}" + suites(IEEE, pairwise) + suites(IEEE, akms) + "0000")


def wpa(pairwise: list, akms: list) -> str:
    return el(221, f"{MS}010100" + f"{MS}{pairwise[0]:02x}" + suites(MS, pairwise) + suites(MS, akms))


OPEN, PRIVACY = 0x0001, 0x0011
CCMP, TKIP, GCMP256 = 4, 2, 9
PSK, EAP, SAE, OWE, SUITE_B = 2, 1, 8, 18, 12

# (bssid, frequency MHz, mean dBm, capability, IEs, present frames)
APS = [
    ("00:00:0c:10:00:01", 2412, -48, OPEN, ssid("CoffeeShop") + RATES_G + HT_CAP + ht_op(1, 0), None),
    ("f4:f2:6d:20:00:02", 2437, -62, PRIVACY, ssid("Neighbour-2G") + RATES_G + HT_CAP + ht_op(6, 1) + rsn([CCMP], [PSK]), None),
    ("00:1b:2f:30:00:03", 2462, -81, OPEN, ssid("PrinterSetup") + RATES_B, None),
    ("b0:be:76:40:00:04", 2437, -70, PRIVACY, ssid("IoT-Hub") + RATES_G + HT_CAP + ht_op(6, 0) + wpa([TKIP], [PSK]) + rsn([CCMP, TKIP], [PSK]), None),
    ("00:14:6c:50:00:05", 2462, -86, PRIVACY, ssid("Grandpa") + RATES_B, (0, 35)),
    ("e8:48:b8:60:00:06", 2412, -74, PRIVACY, ssid("") + RATES_G + HT_CAP + ht_op(1, 0) + rsn([CCMP], [PSK]), None),
    ("f4:f2:6d:20:00:12", 5180, -66, PRIVACY, ssid("Neighbour-5G") + RATES_G + HT_CAP + ht_op(36, 1) + VHT_CAP + vht_op(1, 42) + rsn([CCMP], [PSK]), None),
    ("00:00:0c:70:00:07", 5500, -71, PRIVACY, ssid("Office") + RATES_G + HT_CAP + ht_op(100, 1) + VHT_CAP + vht_op(1, 106, 114) + HE_CAP + rsn([CCMP], [EAP]), None),
    ("00:00:0c:70:00:08", 5745, -58, PRIVACY, ssid("Office-Guest") + RATES_G + HT_CAP + ht_op(149, 1) + VHT_CAP + vht_op(1, 155) + HE_CAP + rsn([CCMP], [OWE]), (20, 60)),
    ("70:a7:41:80:00:09", 6135, -64, PRIVACY, ssid("Neighbour-6E") + RATES_G + HE_CAP + he_op_6ghz(37, 3, 39, 47) + rsn([CCMP], [SAE]), None),
    ("70:a7:41:80:00:0a", 5260, -55, PRIVACY, ssid("Lab-Secure") + RATES_G + HT_CAP + ht_op(52, 1) + VHT_CAP + vht_op(1, 58) + HE_CAP + rsn([GCMP256], [SUITE_B]), None),
    ("f0:9f:c2:90:00:0b", 5180, -77, PRIVACY, ssid("Neighbour-WPA3") + RATES_G + HT_CAP + ht_op(36, 1) + VHT_CAP + vht_op(1, 42) + rsn([CCMP], [PSK, SAE]), None),
]


def main() -> None:
    rng = random.Random(7)
    lines = []
    for frame in range(FRAMES):
        observations = []
        for index, (bssid, freq, mean, capability, ies, present) in enumerate(APS):
            if present and not present[0] <= frame < present[1]:
                continue
            drift = 6 * math.sin(frame / 6 + index)
            observations.append({
                "bssid": bssid,
                "freq_mhz": freq,
                "signal_dbm": round(mean + drift + rng.uniform(-2, 2)),
                "seen_ms_ago": rng.randrange(0, 400),
                "capability": capability,
                "ies": ies,
                "associated": index == 0,
            })
        lines.append(json.dumps({"observations": observations, "passive_reason": None}, separators=(",", ":")))
    OUT.parent.mkdir(parents=True, exist_ok=True)
    OUT.write_text("\n".join(lines) + "\n", encoding="utf-8")
    print(f"wrote {FRAMES} scans of {len(APS)} access points to {OUT}")


if __name__ == "__main__":
    main()
