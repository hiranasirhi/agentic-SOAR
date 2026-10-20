FROM python:3.12-slim

# docker CLI only (no daemon) — needed so mode_control.py can run
# `docker start/stop baseline-dispatcher` against the mounted host socket.
RUN apt-get update && apt-get install -y --no-install-recommends curl ca-certificates gnupg \
    && curl -fsSL https://download.docker.com/linux/debian/gpg -o /tmp/docker.gpg \
    && install -m 0755 -d /etc/apt/keyrings \
    && gpg --dearmor -o /etc/apt/keyrings/docker.gpg /tmp/docker.gpg \
    && echo "deb [arch=$(dpkg --print-architecture) signed-by=/etc/apt/keyrings/docker.gpg] https://download.docker.com/linux/debian $(. /etc/os-release && echo $VERSION_CODENAME) stable" \
       > /etc/apt/sources.list.d/docker.list \
    && apt-get update && apt-get install -y --no-install-recommends docker-ce-cli \
    && apt-get clean && rm -rf /var/lib/apt/lists/*

WORKDIR /app

COPY requirements.txt .
RUN pip install --no-cache-dir -r requirements.txt

COPY . .

# No CMD — this image is run on-demand via `docker compose run evaluation <script> <args>`
