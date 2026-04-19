"""IANA root server hints (current as of 2026-04). Pinned in code for offline use."""

from __future__ import annotations

ROOT_SERVERS: dict[str, dict[str, str]] = {
    "a.root-servers.net": {"v4": "198.41.0.4", "v6": "2001:503:ba3e::2:30"},
    "b.root-servers.net": {"v4": "170.247.170.2", "v6": "2801:1b8:10::b"},
    "c.root-servers.net": {"v4": "192.33.4.12", "v6": "2001:500:2::c"},
    "d.root-servers.net": {"v4": "199.7.91.13", "v6": "2001:500:2d::d"},
    "e.root-servers.net": {"v4": "192.203.230.10", "v6": "2001:500:a8::e"},
    "f.root-servers.net": {"v4": "192.5.5.241", "v6": "2001:500:2f::f"},
    "g.root-servers.net": {"v4": "192.112.36.4", "v6": "2001:500:12::d0d"},
    "h.root-servers.net": {"v4": "198.97.190.53", "v6": "2001:500:1::53"},
    "i.root-servers.net": {"v4": "192.36.148.17", "v6": "2001:7fe::53"},
    "j.root-servers.net": {"v4": "192.58.128.30", "v6": "2001:503:c27::2:30"},
    "k.root-servers.net": {"v4": "193.0.14.129", "v6": "2001:7fd::1"},
    "l.root-servers.net": {"v4": "199.7.83.42", "v6": "2001:500:9f::42"},
    "m.root-servers.net": {"v4": "202.12.27.33", "v6": "2001:dc3::35"},
}

ROOT_IPV4: list[str] = [v["v4"] for v in ROOT_SERVERS.values()]
ROOT_IPV6: list[str] = [v["v6"] for v in ROOT_SERVERS.values()]


PUBLIC_RESOLVERS: dict[str, list[str]] = {
    "Cloudflare": ["1.1.1.1", "1.0.0.1"],
    "Google": ["8.8.8.8", "8.8.4.4"],
    "Quad9": ["9.9.9.9", "149.112.112.112"],
    "OpenDNS": ["208.67.222.222", "208.67.220.220"],
    "ControlD": ["76.76.2.0", "76.76.10.0"],
}


COMMON_DKIM_SELECTORS: list[str] = [
    "default",
    "google",
    "k1",
    "k2",
    "k3",
    "selector1",
    "selector2",
    "s1",
    "s2",
    "mail",
    "dkim",
    "smtp",
    "mandrill",
    "mailjet",
    "sendgrid",
    "pm",
    "postmark",
    "fm1",
    "fm2",
    "fm3",
    "amazonses",
    "key1",
    "key2",
    "mxvault",
    "zoho",
    "20230601",
    "20240101",
    "20250101",
]


# IANA Trust Anchor (KSK-2017, ID 20326). Updated periodically; verify via
# https://data.iana.org/root-anchors/root-anchors.xml
ROOT_KSK_2017_DS = "20326 8 2 e06d44b80b8f1d39a95c0b0d7c65d08458e880409bbc683457104237c7f8ec8d"
