import pytest

from app import merkle


def leaves(n):
    return [merkle.leaf_hash(f"event-{i}".encode()) for i in range(n)]


@pytest.mark.parametrize("n", [1, 2, 3, 4, 5, 7, 8, 13])
def test_every_leaf_has_a_valid_inclusion_proof(n):
    tree = leaves(n)
    top = merkle.root(tree)
    for index, leaf in enumerate(tree):
        assert merkle.verify_proof(leaf, merkle.proof(tree, index), top)


def test_a_changed_leaf_or_wrong_position_fails_verification():
    tree = leaves(6)
    top = merkle.root(tree)
    steps = merkle.proof(tree, 2)
    assert not merkle.verify_proof(merkle.leaf_hash(b"tampered"), steps, top)
    assert not merkle.verify_proof(tree[3], steps, top)


def test_root_depends_on_order_content_and_count():
    tree = leaves(4)
    assert merkle.root(tree) != merkle.root(list(reversed(tree)))
    assert merkle.root(tree) != merkle.root(tree[:3])
    assert merkle.root(tree[:2]) != merkle.root(tree[:2] + [tree[1]])  # no duplicate-leaf collision


def test_leaf_and_node_hashes_are_domain_separated():
    a, b = leaves(2)
    assert merkle.leaf_hash(a + b) != merkle.root([a, b])


def test_empty_tree_is_rejected():
    with pytest.raises(ValueError):
        merkle.root([])
