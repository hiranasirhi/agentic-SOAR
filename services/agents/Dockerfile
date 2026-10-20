FROM python:3.13-slim

WORKDIR /app

ENV PYTHONDONTWRITEBYTECODE=1
ENV PYTHONUNBUFFERED=1

# Paths are relative to the REPO ROOT (build context), not to this folder
COPY services/agents/requirements.txt .

RUN pip install --no-cache-dir -r requirements.txt

COPY services/agents/agents ./agents
COPY shared ./shared

CMD ["python", "-m", "agents.triage_agent"]