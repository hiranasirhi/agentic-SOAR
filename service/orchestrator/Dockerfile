# Build context = project ROOT (the folder that contains BOTH orchestrator/ and shared/)
FROM python:3.12-slim

ENV PYTHONUNBUFFERED=1 \
    PYTHONDONTWRITEBYTECODE=1 \
    PIP_NO_CACHE_DIR=1 \
    HF_HOME=/opt/hf-cache

WORKDIR /app

# psycopg2-binary / chromadb wheels cover most things; build-essential is a safety net
RUN apt-get update \
    && apt-get install -y --no-install-recommends build-essential \
    && rm -rf /var/lib/apt/lists/*

# CPU-only torch first (sentence-transformers would otherwise pull the multi-GB CUDA build)
RUN pip install torch --index-url https://download.pytorch.org/whl/cpu

COPY orchestrator/requirements.txt .
RUN pip install -r requirements.txt

# Bake the embedding model into the image so memory.py doesn't download it at runtime
RUN python -c "from sentence_transformers import SentenceTransformer; SentenceTransformer('all-MiniLM-L6-v2')"

# Application code. `shared` is imported by main.py and react_engine.py.
COPY orchestrator ./orchestrator
COPY shared ./shared

# Non-root user + writable ChromaDB dir (mounted as a volume in compose)
RUN useradd -m appuser \
    && mkdir -p /data/chromadb_store \
    && chown -R appuser:appuser /app /data /opt/hf-cache
USER appuser

ENV CHROMADB_PATH=/data/chromadb_store \
    ORCHESTRATOR_HOST=0.0.0.0 \
    ORCHESTRATOR_PORT=8000

EXPOSE 8000

# ONE worker only: main.py starts a Kafka consumer + stale-task recovery thread at
# import/startup, so multiple workers would duplicate them.
CMD ["uvicorn", "orchestrator.main:app", "--host", "0.0.0.0", "--port", "8000"]
