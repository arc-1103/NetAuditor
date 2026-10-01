"""
Pattern-based keyword extraction for configuration syntax the parser did not
recognize.

For an unknown block this finds the command words that are NOT in a general
network-CLI vocabulary, ranks them (more frequent, and words in command
position, rank higher) and marks the ones that look security-relevant, so the
person teaching the system sees what is actually unfamiliar instead of a wall
of text. It is deterministic word analysis, not a language model: it never
invents meaning, it only says "this word is unfamiliar and appears here".
"""

import re
from collections import Counter

# Common words across major vendors' CLIs. Anything outside this set is
# "unfamiliar" — extend it as the system learns.
KNOWN_VOCABULARY = frozenset("""
aaa access access-class access-group access-list accounting action address address-family admin
alert allow any area arp authentication authorization auto banner bgp bridge broadcast buffer
cdp certificate class clock community config configure console crypto default delete deny description
destination device dhcp disable domain domain-name duplex edit enable encapsulation encryption end
ethernet exec exit family filter firewall flow forward from gateway global group hash host hostname
http https icmp identity inbound input interface ip ipsec isakmp key keychain lacp level line lldp
local log logging login loopback mac management map mask match max member mode monitor mtu name
negotiation neighbor network next no ntp object ospf outbound output password peer permit policy
pool port prefix priority privilege profile protocol proxy radius range redistribute remote-as
route router routing rule secret security server service session set shutdown snmp snmp-server
source speed spanning-tree ssh standard static status switchport syslog system tacacs tacacs+ telnet
gigabitethernet tengigabitethernet fastethernet port-channel portchannel mgmt null
timeout timestamps traffic transport trap trunk trusted-key trust tunnel type udp user username
version vlan vpn vrf vty zone allowaccess trusthost pre-login-banner post-login-banner
""".split())

SECURITY_HINTS = (
    "auth", "pass", "secret", "key", "crypt", "cert", "token", "snmp", "acl", "ssh", "tls", "ssl",
    "radius", "tacacs", "firewall", "vpn", "ipsec", "ike", "trust", "admin", "login", "banner",
    "audit", "encrypt", "hash", "permit", "deny", "policy", "zone",
)
# Words only: a token with a digit in it ("gi0", "eth1", "ge-0/0/0") is an
# identifier, not a command keyword.
_WORD = re.compile(r"(?<![A-Za-z0-9_+-])[A-Za-z][A-Za-z_+-]{2,}(?![A-Za-z0-9_+-])")
_QUOTED = re.compile(r"\"[^\"]*\"|'[^']*'")
_COMMENT_PREFIXES = ("!", "#", "//", ";")


def extract_unfamiliar_keywords(raw_text: str, *, limit: int = 8) -> list[dict]:
    counts: Counter[str] = Counter()
    command_position: set[str] = set()
    example: dict[str, str] = {}

    for line in raw_text.splitlines():
        stripped = line.strip()
        if not stripped or stripped.startswith(_COMMENT_PREFIXES):
            continue
        words = _WORD.findall(_QUOTED.sub(" ", stripped))
        for index, word in enumerate(words):
            key = word.lower()
            if key in KNOWN_VOCABULARY:
                continue
            counts[key] += 1
            example.setdefault(key, stripped[:120])
            if index == 0:
                command_position.add(key)

    def score(key: str) -> tuple[int, str]:
        return -(counts[key] + (2 if key in command_position else 0)), key

    return [
        {
            "keyword": key,
            "count": counts[key],
            "command_position": key in command_position,
            "security_related": any(hint in key for hint in SECURITY_HINTS),
            "example": example[key],
        }
        for key in sorted(counts, key=score)[:limit]
    ]
