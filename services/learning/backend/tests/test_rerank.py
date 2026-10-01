from app.rerank import rerank


def result():
    return {"ids": [["a", "b", "c"]], "documents": [["x", "y", "z"]], "metadatas": [[{}, {}, {}]],
            "distances": [[0.1, 0.2, 0.3]], "fusion_scores": [[0.03, 0.02, 0.01]]}


def test_cross_encoder_order_wins_and_distances_follow_their_documents():
    out = rerank(result(), "q", 2, scorer=lambda q, docs: [0.1, 0.2, 0.9])
    assert out["ids"][0] == ["c", "b"]
    assert out["distances"][0] == [0.3, 0.2]
    assert out["fusion_scores"][0] == [0.01, 0.02]


def test_model_failure_keeps_fused_order_and_says_so():
    def boom(q, docs):
        raise OSError("no model offline")

    out = rerank(result(), "q", 2, scorer=boom)
    assert out["ids"][0] == ["a", "b"] and out["rerank"].startswith("skipped")
