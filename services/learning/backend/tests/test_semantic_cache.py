from app import semantic_cache as sc

V = [1.0, 0.0, 0.0]
NEAR = [0.999, 0.02, 0.0]
FAR = [0.0, 1.0, 0.0]
CISCO = ("cisco", "ios")


def setup_function():
    sc.clear()


def test_near_identical_query_hits_and_unrelated_misses():
    sc.store("ip access-group 101 in", V, CISCO, {"ids": [["a"]]})
    assert sc.lookup("ip  access-group 101 in", NEAR, CISCO) == {"ids": [["a"]]}
    assert sc.lookup("ntp server", FAR, CISCO) is None


def test_different_acl_number_never_reuses_the_result():
    sc.store("ip access-group 101 in", V, CISCO, {"ids": [["a"]]})
    assert sc.lookup("ip access-group 102 in", V, CISCO) is None


def test_other_vendor_scope_never_hits():
    sc.store("snmp-server community public", V, CISCO, {"ids": [["a"]]})
    assert sc.lookup("snmp-server community public", V, ("juniper", "junos")) is None


def test_entries_expire_and_clear_invalidates():
    sc.store("q 1", V, CISCO, {"x": 1}, now=0)
    assert sc.lookup("q 1", V, CISCO, now=sc.TTL_SECONDS + 1) is None
    sc.store("q 1", V, CISCO, {"x": 1})
    sc.clear()
    assert sc.lookup("q 1", V, CISCO) is None
