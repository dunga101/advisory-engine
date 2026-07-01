FROM python:3.12-slim

WORKDIR /app

COPY publisher/requirements.txt publisher/requirements.txt
RUN pip install --no-cache-dir -r publisher/requirements.txt

COPY common/ common/
COPY publisher/ publisher/

ENV PYTHONPATH=/app

CMD ["python", "publisher/main.py"]
