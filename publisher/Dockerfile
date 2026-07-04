FROM python:3.12-slim

RUN apt-get update \
    && apt-get install -y --no-install-recommends git \
    && rm -rf /var/lib/apt/lists/*

WORKDIR /app

COPY publisher/requirements.txt publisher/requirements.txt
RUN pip install --no-cache-dir -r publisher/requirements.txt

COPY common/ common/
COPY scripts/ scripts/
COPY publisher/ publisher/

ENV PYTHONPATH=/app

CMD ["python", "publisher/main.py"]
