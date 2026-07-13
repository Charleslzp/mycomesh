FROM python:3.11-slim

ENV PYTHONDONTWRITEBYTECODE=1 \
    PYTHONUNBUFFERED=1 \
    PIP_NO_CACHE_DIR=1 \
    PYTHONPATH=/app \
    MYCOMESH_DATA_DIR=/data

WORKDIR /app

COPY requirements.txt pyproject.toml README.md ./
COPY gateway ./gateway
COPY deployments ./deployments
COPY agents.example.json ./agents.example.json

RUN pip install --upgrade pip \
    && pip install -r requirements.txt

RUN printf '#!/bin/sh\nexec python -m gateway "$@"\n' > /usr/local/bin/mycomesh \
    && chmod +x /usr/local/bin/mycomesh

RUN mkdir -p /data

VOLUME ["/data"]
EXPOSE 8000 8100 9700 9800 9900 9901

ENTRYPOINT ["python", "-m", "gateway"]
CMD ["serve", "--host", "0.0.0.0", "--port", "8000"]
