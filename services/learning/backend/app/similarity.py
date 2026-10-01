"""
Semantic neighbours of an unrecognised configuration block, for the Learning
queue's explanation view.

Every number is computed from the stored embeddings, not asserted:
  * similarity  = cosine similarity between the block's embedding and each
                  previously confirmed mapping's embedding;
  * x, y        = a 2-D PCA projection of those same vectors, so points that
                  are close in the plot really are close in embedding space
                  (a projection loses information; the cosine value is exact).
"""

import numpy as np


def cosine(a: np.ndarray, b: np.ndarray) -> float:
    denominator = float(np.linalg.norm(a) * np.linalg.norm(b))
    return float(np.dot(a, b) / denominator) if denominator else 0.0


def project_2d(vectors: np.ndarray) -> np.ndarray:
    """PCA to two dimensions. Fewer than two vectors or dimensions pad with zeros."""
    count = len(vectors)
    if count == 0:
        return np.zeros((0, 2))
    centered = vectors - vectors.mean(axis=0)
    if count < 2:
        return np.zeros((count, 2))
    _, _, components = np.linalg.svd(centered, full_matrices=False)
    projected = centered @ components[:2].T
    if projected.shape[1] < 2:
        projected = np.hstack([projected, np.zeros((count, 2 - projected.shape[1]))])
    return projected


def neighbours(query_vector, confirmed: list[dict], limit: int = 8) -> dict:
    """confirmed: [{"id", "vector", "metadata": {cli_pattern, field, value}}]"""
    if not confirmed:
        return {"points": [], "query": None, "best": None,
                "note": "No mappings have been confirmed yet, so there is nothing to compare this block with. The first mapping you teach becomes the first reference point."}
    query = np.asarray(query_vector, dtype=float)
    matrix = np.vstack([query] + [np.asarray(c["vector"], dtype=float) for c in confirmed])
    coordinates = project_2d(matrix)
    scale = float(np.abs(coordinates).max()) or 1.0
    coordinates = coordinates / scale  # fit the plot area: -1..1
    points = []
    for index, item in enumerate(confirmed, start=1):
        meta = item.get("metadata") or {}
        points.append({
            "id": item["id"], "x": round(float(coordinates[index][0]), 4), "y": round(float(coordinates[index][1]), 4),
            "similarity": round(cosine(query, matrix[index]), 4),
            "cli_pattern": meta.get("cli_pattern"), "field": meta.get("field"), "value": meta.get("value"),
        })
    points.sort(key=lambda p: -p["similarity"])
    return {
        "query": {"x": round(float(coordinates[0][0]), 4), "y": round(float(coordinates[0][1]), 4)},
        "points": points[: max(limit, 1)] if len(points) > limit else points,
        "best": points[0], "total_confirmed": len(points), "note": None,
    }
