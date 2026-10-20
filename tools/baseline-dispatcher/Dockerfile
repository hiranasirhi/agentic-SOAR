FROM python:3.12-slim

WORKDIR /app

COPY requirements.txt .
RUN pip install --no-cache-dir -r requirements.txt

COPY rules.py dispatcher.py .

CMD ["python", "dispatcher.py"]
