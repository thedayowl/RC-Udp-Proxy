FROM python:3.13-slim

ENV PYTHONUNBUFFERED=1 \
    PYTHONDONTWRITEBYTECODE=1 \
    RCPROXY_DATA=/data \
    WEB_PORT=8080

WORKDIR /app
COPY requirements.txt .
RUN pip install --no-cache-dir -r requirements.txt

COPY rcproxy ./rcproxy

VOLUME ["/data"]
EXPOSE 5060/udp 8080/tcp

HEALTHCHECK --interval=30s --timeout=5s --start-period=10s \
  CMD python -c "import socket; s=socket.create_connection(('127.0.0.1', int(__import__('os').environ.get('WEB_PORT','8080'))), 3); s.close()" || exit 1

CMD ["python", "-m", "rcproxy"]
