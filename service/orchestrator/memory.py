# orchestrator/memory.py
# ChromaDB long-term memory for PROTEGO
# Two collections: incidents and false_positives
#
# ChromaDB is initialized LAZILY and NON-FATALLY. Importing this module
# never touches ChromaDB, so a ChromaDB problem (version mismatch,
# corrupted store, missing embedding model, ...) can no longer stop the
# orchestrator from starting. While memory is unavailable every function
# degrades to a safe default (empty retrieval / no false-positive match /
# store returns False) and the orchestrator keeps generating and
# dispatching task plans from current incident context only.

import os
import threading
import time
from datetime import datetime

from dotenv import load_dotenv

load_dotenv()

import chromadb
from chromadb.utils import embedding_functions

INCIDENT_SIMILARITY_THRESHOLD = float(
    os.getenv(
        "INCIDENT_SIMILARITY_THRESHOLD",
        "0.50"
    )
)

CHROMADB_PATH = os.getenv("CHROMADB_PATH", "./chromadb_store")

# Minimum gap between initialization attempts triggered by normal
# requests, so a broken ChromaDB is not re-attempted (and the embedding
# model not re-loaded) on every single call.
MEMORY_RETRY_COOLDOWN_SECONDS = int(
    os.getenv("MEMORY_RETRY_COOLDOWN_SECONDS", "30")
)

# ============================================
# LAZY CHROMADB STATE
# ============================================

_client = None
_embedding_fn = None
_incidents_collection = None
_false_positives_collection = None

_init_lock = threading.Lock()
_last_attempt = 0.0
_last_error = None


def _is_ready() -> bool:
    return (
        _incidents_collection is not None
        and _false_positives_collection is not None
    )


def _try_init() -> bool:
    """
    Attempt to initialize ChromaDB. Never raises.

    Uses a NON-blocking lock: if another thread is already initializing
    (e.g. the startup warm-up thread), callers return False immediately
    instead of piling up behind a slow model load.
    """
    global _client, _embedding_fn
    global _incidents_collection, _false_positives_collection
    global _last_attempt, _last_error

    if not _init_lock.acquire(blocking=False):
        return False

    try:
        if _is_ready():
            return True

        _last_attempt = time.time()

        try:
            print("Initializing ChromaDB collections...")

            if _embedding_fn is None:
                _embedding_fn = (
                    embedding_functions.SentenceTransformerEmbeddingFunction(
                        model_name="all-MiniLM-L6-v2"
                    )
                )

            if _client is None:
                _client = chromadb.PersistentClient(path=CHROMADB_PATH)

            incidents = _client.get_or_create_collection(
                name="incidents",
                embedding_function=_embedding_fn,
                metadata={
                    "description": (
                        "Behavioral timelines of resolved security incidents"
                    )
                },
            )

            false_positives = _client.get_or_create_collection(
                name="false_positives",
                embedding_function=_embedding_fn,
                metadata={
                    "description": (
                        "Patterns confirmed as false positives by analysts"
                    )
                },
            )

            _incidents_collection = incidents
            _false_positives_collection = false_positives
            _last_error = None

            print("[MEMORY] ChromaDB ready")
            print(f"incidents collection: {incidents.count()} records")
            print(
                f"false_positives collection: "
                f"{false_positives.count()} records"
            )
            return True

        except Exception as e:
            _last_error = f"{type(e).__name__}: {e}"
            print(f"[MEMORY] ChromaDB unavailable: {_last_error}")
            return False

    finally:
        _init_lock.release()


def _ensure_ready() -> bool:
    """True if memory is usable. Retries at most once per cooldown."""
    if _is_ready():
        return True

    if time.time() - _last_attempt < MEMORY_RETRY_COOLDOWN_SECONDS:
        return False

    return _try_init()


def memory_available() -> bool:
    """Cheap status check for callers (does not trigger initialization)."""
    return _is_ready()


def warmup(retry_seconds: int = 15):
    """
    Run in a daemon thread at orchestrator startup:

        threading.Thread(target=memory.warmup, daemon=True).start()

    Loads the embedding model and opens ChromaDB in the background (so
    the first incident does not pay that cost) and keeps retrying until
    ChromaDB is healthy. Never raises, never blocks startup.
    """
    while not _is_ready():
        if _try_init():
            return
        time.sleep(retry_seconds)


# ============================================
# STORE INCIDENT (called by Learning Agent after closure)
# ============================================

def store_incident(
    incident_id: str,
    behavioral_timeline: str,
    outcome: str,
    resolution_time_minutes: int,
    false_positive: bool = False,
    notes: str = ""
):
    # Returning False (not raising) lets the Learning Agent leave the
    # incident un-"learned" in PostgreSQL so it is retried later.
    if not _ensure_ready():
        print(
            f"[MEMORY] Not stored (ChromaDB unavailable): {incident_id}"
        )
        return False

    try:
        existing = _incidents_collection.get(ids=[incident_id])
        metadata = {
            "incident_id": incident_id,
            "outcome": outcome,
            "resolution_time_minutes": resolution_time_minutes,
            "false_positive": str(false_positive),
            "notes": notes,
            "timestamp": datetime.now().isoformat(),
            "synthetic": "false"
        }

        if existing["ids"]:
            print(f"Incident {incident_id} already in ChromaDB, updating...")
            _incidents_collection.update(
                ids=[incident_id],
                documents=[behavioral_timeline],
                metadatas=[metadata]
            )
        else:
            _incidents_collection.add(
                ids=[incident_id],
                documents=[behavioral_timeline],
                metadatas=[metadata]
            )

        print(f"Stored incident {incident_id} in ChromaDB incidents collection")
        print(f"  Outcome: {outcome}")
        print(f"  Resolution: {resolution_time_minutes} minutes")
        return True

    except Exception as e:
        print(f"Error storing incident {incident_id}: {e}")
        return False

# ============================================
# STORE FALSE POSITIVE (called when analyst marks FP)
# ============================================

def store_false_positive(incident_id: str, behavioral_pattern: str, reason: str = ""):
    if not _ensure_ready():
        print(
            f"[MEMORY] False positive not stored "
            f"(ChromaDB unavailable): {incident_id}"
        )
        return False

    try:
        fp_id = f"fp_{incident_id}"

        existing = _false_positives_collection.get(ids=[fp_id])
        if existing["ids"]:
            print(f"FP pattern {fp_id} already exists")
            return True

        _false_positives_collection.add(
            ids=[fp_id],
            documents=[behavioral_pattern],
            metadatas=[{
                "incident_id": incident_id,
                "reason": reason,
                "timestamp": datetime.now().isoformat()
            }]
        )

        print(f"Stored false positive pattern for {incident_id}")
        print(f"  Reason: {reason}")
        print(f"  Future similar incidents will get -2 severity discount")
        return True

    except Exception as e:
        print(f"Error storing false positive: {e}")
        return False

# ============================================
# RETRIEVE SIMILAR INCIDENTS (RAG retrieval)
# ============================================

def retrieve_similar_incidents(query: str, n_results: int = 3) -> list:
    """
    Returns list of dicts with keys: behavioral_timeline, metadata,
    similarity, incident_id. Returns [] if memory is unavailable.

    NOTE: prefer retrieve_context() below when you also need the false
    positive check for the same query text — it embeds the query once
    and reuses that embedding for both collections instead of paying
    for the SentenceTransformer embedding twice. This function is kept
    standalone for callers (e.g. the now-unused retrieve_past_incidents
    tool) that only need incident similarity.
    """
    if not _ensure_ready():
        return []

    try:
        if _incidents_collection.count() == 0:
            print("ChromaDB incidents collection is empty")
            return []

        results = _incidents_collection.query(
            query_texts=[query],
            n_results=min(n_results, _incidents_collection.count())
        )

        return _format_similar(results)

    except Exception as e:
        print(f"ChromaDB retrieval error: {e}")
        return []


def _format_similar(results) -> list:
    similar = []

    if results["documents"] and results["documents"][0]:
        for i in range(len(results["documents"][0])):
            distance = results["distances"][0][i]
            similarity = 1 - distance

            similar.append({
                "behavioral_timeline": results["documents"][0][i],
                "metadata": results["metadatas"][0][i],
                "similarity": round(similarity, 3),
                "incident_id": results["ids"][0][i]
            })

    print(f"ChromaDB found {len(similar)} similar past incidents")
    for s in similar:
        print(f"  {s['incident_id']}: similarity={s['similarity']}")

    return similar

# ============================================
# CHECK FALSE POSITIVE HISTORY
# ============================================

def check_false_positive(query: str, similarity_threshold: float = 0.80) -> dict:
    """
    Standalone false-positive check. Prefer retrieve_context() when you
    also need similar-incident retrieval for the same query — see note
    on retrieve_similar_incidents above. If memory is unavailable this
    reports "not a false positive" so triage proceeds normally.
    """
    if not _ensure_ready():
        return {"is_false_positive_pattern": False}

    try:
        if _false_positives_collection.count() == 0:
            return {"is_false_positive_pattern": False}

        results = _false_positives_collection.query(
            query_texts=[query],
            n_results=1
        )

        return _format_fp_result(results, similarity_threshold)

    except Exception as e:
        print(f"FP check error: {e}")
        return {"is_false_positive_pattern": False}


def _format_fp_result(results, similarity_threshold: float) -> dict:
    if not results["distances"] or not results["distances"][0]:
        return {"is_false_positive_pattern": False}

    distance = results["distances"][0][0]
    similarity = 1 - distance

    if similarity >= similarity_threshold:
        matched_id = results["ids"][0][0]
        metadata = results["metadatas"][0][0]

        print(f"FALSE POSITIVE PATTERN DETECTED!")
        print(f"  Matched: {matched_id}")
        print(f"  Similarity: {similarity:.1%}")
        print(f"  Reason: {metadata.get('reason', 'Not specified')}")

        return {
            "is_false_positive_pattern": True,
            "similarity": round(similarity, 3),
            "matched_incident_id": matched_id,
            "reason": metadata.get("reason", ""),
            "original_timestamp": metadata.get("timestamp", "")
        }
    else:
        return {
            "is_false_positive_pattern": False,
            "closest_similarity": round(similarity, 3)
        }

# ============================================
# COMBINED RETRIEVAL (embeds query ONCE, queries both collections)
# ============================================

def retrieve_context(query: str, n_results: int = 3, fp_similarity_threshold: float = 0.80) -> dict:
    """
    Single entry point for the orchestrator hot path. Embeds `query`
    exactly once via the shared embedding function, then reuses that
    vector to query both the incidents and false_positives collections
    with query_embeddings= instead of query_texts=. Avoids computing the
    same sentence embedding twice per incident (previously:
    retrieve_similar_incidents + check_false_positive each embedded
    the identical query string independently).

    Returns: {"similar_incidents": [...], "fp_check": {...},
              "memory_available": bool}

    If ChromaDB is unavailable this returns empty retrieval immediately
    (memory_available=False) so incident processing is never blocked.
    """
    if not _ensure_ready():
        return {
            "similar_incidents": [],
            "fp_check": {"is_false_positive_pattern": False},
            "memory_available": False,
        }

    try:
        # embedding_fn(["text", ...]) -> list of vectors (Chroma's
        # EmbeddingFunction __call__ contract).
        query_embedding = _embedding_fn([query])
    except Exception as e:
        print(f"Embedding computation failed: {e}. Falling back to per-call embedding.")
        return {
            "similar_incidents": retrieve_similar_incidents(query, n_results),
            "fp_check": check_false_positive(query, fp_similarity_threshold),
            "memory_available": True,
        }

    # ---- similar incidents ----
    similar_incidents = []
    try:
        if _incidents_collection.count() > 0:
            results = _incidents_collection.query(
                query_embeddings=query_embedding,
                n_results=min(n_results, _incidents_collection.count()),
            )

            similar_incidents = _format_similar(results)

            similar_incidents = [
                incident
                for incident in similar_incidents
                if incident.get("similarity", 0)
                >= INCIDENT_SIMILARITY_THRESHOLD
            ]

            print(
                f"[MEMORY] Kept {len(similar_incidents)} "
                f"incidents above similarity threshold "
                f"{INCIDENT_SIMILARITY_THRESHOLD:.0%}"
            )

        else:
            print("ChromaDB incidents collection is empty")
    except Exception as e:
        print(f"ChromaDB incidents retrieval error: {e}")

    # ---- false positive check ----
    fp_check = {"is_false_positive_pattern": False}
    try:
        if _false_positives_collection.count() > 0:
            fp_results = _false_positives_collection.query(
                query_embeddings=query_embedding,
                n_results=1,
            )
            fp_check = _format_fp_result(fp_results, fp_similarity_threshold)
    except Exception as e:
        print(f"FP check error: {e}")

    return {
        "similar_incidents": similar_incidents,
        "fp_check": fp_check,
        "memory_available": True,
    }

# ============================================
# FORMAT RETRIEVED CONTEXT FOR LLM
# ============================================

def format_context_for_llm(similar_incidents: list) -> str:
    if not similar_incidents:
        return "No similar past incidents found in memory. This may be a novel attack pattern. Reason from current incident context only."

    context = f"RETRIEVED PAST INCIDENTS ({len(similar_incidents)} similar cases found):\n\n"

    for i, incident in enumerate(similar_incidents, 1):
        metadata = incident.get("metadata", {})
        similarity = incident.get("similarity", 0)
        outcome = metadata.get("outcome", "UNKNOWN")
        resolution_time = metadata.get("resolution_time_minutes", "unknown")
        false_positive = metadata.get("false_positive", "false")
        notes = metadata.get("notes", "")

        context += f"--- Past Incident {i} (Similarity: {similarity:.0%}) ---\n"
        context += f"Attack Pattern: {incident.get('behavioral_timeline', 'N/A')}\n"
        context += f"Outcome: {outcome}\n"
        context += f"Resolution Time: {resolution_time} minutes\n"

        if false_positive == "true":
            context += f"NOTE: This was a FALSE POSITIVE. No real threat.\n"

        if notes:
            context += f"Notes: {notes}\n"

        context += "\n"

    context += "Use these past cases to inform your response plan. If a similar case was a false positive, consider reducing severity and routing to monitoring only.\n"

    return context

# ============================================
# GET COLLECTION STATS
# ============================================

def get_memory_stats() -> dict:
    """Never raises: reports degraded status if ChromaDB is unavailable."""
    if not _ensure_ready():
        return {
            "available": False,
            "error": _last_error,
            "incidents_count": None,
            "false_positives_count": None,
            "chromadb_path": CHROMADB_PATH,
        }

    try:
        return {
            "available": True,
            "error": None,
            "incidents_count": _incidents_collection.count(),
            "false_positives_count": _false_positives_collection.count(),
            "chromadb_path": CHROMADB_PATH,
        }
    except Exception as e:
        return {
            "available": False,
            "error": f"{type(e).__name__}: {e}",
            "incidents_count": None,
            "false_positives_count": None,
            "chromadb_path": CHROMADB_PATH,
        }
