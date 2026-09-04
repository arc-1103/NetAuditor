"""
Compliance service — the deterministic half of the pipeline.

Owns: the versioned Rego policy bundle under ../policies/, evaluation of a
normalized SecurityBaseline against it via OPA, risk scoring of the
resulting findings, and their persistence to Postgres. Nothing in this
lane is probabilistic — the same baseline always yields the same verdict.
See ../README.md for the request flow.
"""

__version__ = "0.1.0"
