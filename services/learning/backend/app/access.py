"""Access control for every ChromaDB collection.

Each stored chunk carries an `access_tier` tag:

  public  shipped or non-sensitive content, readable by every authenticated role;
  admin   proprietary content (confirmed mappings, vendor manual excerpts,
          non-seed vendor fingerprints, baseline vectors), readable only by
          elevated roles.

The tier is applied as a metadata pre-filter inside ChromaDB, before any
similarity ranking, so a chunk the caller may not read is never even a
candidate. Endpoint code never touches a raw collection: it gets a
ScopedCollection, whose query/get merge the filter unconditionally and whose
writes refuse untagged chunks. A test scans the source to keep it that way.

Roles come only from a verified service token (app/service_token.py):

  admin           a human administrator (via the gateway): reads and writes both tiers;
  service_worker  the internal principal Parsing, Compliance and Remediation
                  sign as, so pipeline grounding can read admin-tier mappings
                  instead of silently dropping to the lowest level;
  operator / auditor / anything else: public tier, read only.

service_worker is a deliberate elevated tier: anyone holding SERVICE_JWT_SECRET
can mint it (see service_token.py), which is why the secret never leaves the
internal network.
"""
import logging

logger = logging.getLogger(__name__)

PUBLIC = "public"
ADMIN = "admin"
TIERS = (PUBLIC, ADMIN)
ELEVATED_ROLES = {"admin", "service_worker"}
# Chunks written before tiering existed carry no tag; treat them as proprietary.
LEGACY_TIER = ADMIN

_backfilled: set[str] = set()


class AccessDenied(PermissionError):
    pass


def role_of(claims) -> str:
    return str(claims.get("role", "")).lower() if isinstance(claims, dict) else ""  # non-dict = unauthenticated direct call


def visible_tiers(claims) -> list[str]:
    return list(TIERS) if role_of(claims) in ELEVATED_ROLES else [PUBLIC]


def check_tier(tier) -> str:
    if tier not in TIERS:
        raise ValueError(f"access_tier must be one of {list(TIERS)}")
    return tier


def scoped_where(claims, extra: dict | None = None) -> dict:
    tier = {"access_tier": {"$in": visible_tiers(claims)}}
    return {"$and": [tier, extra]} if extra else tier


def backfill(collection) -> None:
    name = getattr(collection, "name", None) or str(id(collection))
    if name in _backfilled:
        return
    stored = collection.get(include=["metadatas"])
    ids = [i for i, m in zip(stored.get("ids") or [], stored.get("metadatas") or []) if "access_tier" not in (m or {})]
    if ids:
        collection.update(ids=ids, metadatas=[{"access_tier": LEGACY_TIER}] * len(ids))
        logger.warning("Tagged %d untiered chunk(s) in %s as %s", len(ids), name, LEGACY_TIER)
    _backfilled.add(name)


class ScopedCollection:
    """A ChromaDB collection seen through one caller's claims."""

    def __init__(self, collection, claims):
        self._c = collection
        self.claims = claims

    def query(self, *, where: dict | None = None, **kwargs):
        return self._c.query(where=scoped_where(self.claims, where), **kwargs)

    def get(self, *, where: dict | None = None, **kwargs):
        return self._c.get(where=scoped_where(self.claims, where), **kwargs)

    def count(self) -> int:
        return self._c.count()

    def upsert(self, *, ids, documents, metadatas):
        if role_of(self.claims) not in ELEVATED_ROLES:
            raise AccessDenied("only an elevated role may write to the knowledge index")
        for meta in metadatas:
            check_tier((meta or {}).get("access_tier"))  # no chunk enters the index untagged
        return self._c.upsert(ids=ids, documents=documents, metadatas=metadatas)


def scoped(collection, claims) -> ScopedCollection:
    return ScopedCollection(collection, claims)
