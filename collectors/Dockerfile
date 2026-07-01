FROM python:3.12-slim

WORKDIR /app

COPY collectors/requirements.txt collectors/requirements.txt
RUN pip install --no-cache-dir -r collectors/requirements.txt

COPY common/ common/
COPY db/ db/
COPY collectors/ collectors/
COPY scripts/ scripts/

ENV PYTHONPATH=/app

CMD ["python", "collectors/scheduler.py"]
