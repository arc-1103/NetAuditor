from app.keywords import extract_unfamiliar_keywords


BLOCK = """
! proprietary zone-firewall syntax
ztna-gateway enable
ztna-gateway posture-check strict
interface Gi0/1
 description "uplink ignore-this-quoted-word"
 ip address 10.0.0.1 255.255.255.0
quarantine-vlan 999
"""


def test_unfamiliar_words_are_found_and_ranked_with_command_position_first():
    found = extract_unfamiliar_keywords(BLOCK)
    names = [k["keyword"] for k in found]
    assert names[0] == "ztna-gateway"
    assert {"posture-check", "strict", "quarantine-vlan"} <= set(names)
    top = found[0]
    assert top["count"] == 2 and top["command_position"] and top["example"].startswith("ztna-gateway")


def test_known_vocabulary_comments_and_quoted_text_are_ignored():
    names = {k["keyword"] for k in extract_unfamiliar_keywords(BLOCK)}
    assert not names & {"interface", "description", "address", "enable", "proprietary", "ignore-this-quoted-word"}


def test_security_related_words_are_flagged():
    found = {k["keyword"]: k for k in extract_unfamiliar_keywords("radius-proxy-auth on\nfoo-widget on\n")}
    assert found["radius-proxy-auth"]["security_related"] is True
    assert found["foo-widget"]["security_related"] is False


def test_empty_or_fully_known_text_gives_no_keywords_and_limit_is_respected():
    assert extract_unfamiliar_keywords("interface Gi0/1\n ip address 10.0.0.1 255.255.255.0\n") == []
    many = "\n".join(f"zzword{chr(97 + i)}x value" for i in range(20))
    assert len(extract_unfamiliar_keywords(many, limit=5)) == 5
