import numpy as np
import pytest

from app import similarity


def item(i, vector, field="ssh.management_acl"):
    return {"id": f"m{i}", "vector": vector, "metadata": {"cli_pattern": f"pattern-{i}", "field": field, "value": "x"}}


def test_cosine_values_are_exact():
    assert similarity.cosine(np.array([1, 0]), np.array([1, 0])) == pytest.approx(1.0)
    assert similarity.cosine(np.array([1, 0]), np.array([0, 1])) == pytest.approx(0.0)
    assert similarity.cosine(np.array([1, 1]), np.array([-1, -1])) == pytest.approx(-1.0)
    assert similarity.cosine(np.array([0, 0]), np.array([1, 1])) == 0.0


def test_nearest_confirmed_mapping_ranks_first_with_its_true_similarity():
    query = [1.0, 0.2, 0.0]
    result = similarity.neighbours(query, [item(1, [0.0, 1.0, 0.0]), item(2, [1.0, 0.25, 0.0]), item(3, [-1.0, 0.0, 0.0])])
    assert [p["id"] for p in result["points"]] == ["m2", "m1", "m3"]
    assert result["best"]["id"] == "m2" and result["best"]["similarity"] == pytest.approx(0.9991, abs=1e-3)
    assert result["points"][-1]["similarity"] < 0
    assert result["best"]["field"] == "ssh.management_acl"


def test_projection_keeps_close_vectors_close_and_fits_the_plot_area():
    rng = np.random.default_rng(0)
    base = rng.normal(size=8)
    confirmed = [item(1, (base + rng.normal(scale=0.01, size=8)).tolist()),
                 item(2, rng.normal(size=8).tolist()), item(3, rng.normal(size=8).tolist())]
    result = similarity.neighbours(base.tolist(), confirmed)
    near = next(p for p in result["points"] if p["id"] == "m1")
    far = [p for p in result["points"] if p["id"] != "m1"]
    distance = lambda p: ((p["x"] - result["query"]["x"]) ** 2 + (p["y"] - result["query"]["y"]) ** 2) ** 0.5
    assert distance(near) < min(distance(p) for p in far)
    assert all(abs(v) <= 1.0001 for p in result["points"] for v in (p["x"], p["y"]))


def test_no_confirmed_mappings_says_so_instead_of_inventing_neighbours():
    result = similarity.neighbours([1.0, 0.0], [])
    assert result["points"] == [] and result["best"] is None and "No mappings have been confirmed" in result["note"]


def test_single_reference_still_projects():
    result = similarity.neighbours([1.0, 0.0], [item(1, [0.9, 0.1])])
    assert len(result["points"]) == 1 and result["best"]["similarity"] > 0.9
