from app.hybrid import bm25_scores, fuse


def result(docs, dists):
    return {"ids": [[f"d{i}" for i in range(len(docs))]], "documents": [docs], "metadatas": [[{}] * len(docs)], "distances": [dists]}


def test_bm25_separates_near_identical_cli_lines_dense_cannot():
    scores = bm25_scores("ip access-group 102 in", ["ip access-group 101 in", "ip access-group 102 in"])
    assert scores[1] > scores[0]


def test_lexical_match_outranks_a_slightly_closer_dense_match():
    # dense order: d0 (closest), d1, d2 — but only d2 contains the exact ACL name
    r = result(["ntp server a", "snmp community x", "ip access-group MGMT-ONLY in"], [0.30, 0.31, 0.33])
    out = fuse(r, "access-group MGMT-ONLY", top_k=3)
    assert out["ids"][0][0] == "d2"


def test_true_cosine_distance_is_preserved_and_top_k_applied():
    r = result(["a b", "c d", "e f"], [0.1, 0.2, 0.3])
    out = fuse(r, "e", top_k=2)
    assert len(out["ids"][0]) == 2
    for doc_id, dist in zip(out["ids"][0], out["distances"][0]):
        assert dist == {"d0": 0.1, "d1": 0.2, "d2": 0.3}[doc_id]


def test_no_lexical_overlap_keeps_dense_order():
    out = fuse(result(["alpha", "beta", "gamma"], [0.1, 0.2, 0.3]), "zzz", top_k=3)
    assert out["ids"][0] == ["d0", "d1", "d2"]


def test_empty_result_passes_through():
    assert fuse({"ids": [[]]}, "q", 5) == {"ids": [[]]}
