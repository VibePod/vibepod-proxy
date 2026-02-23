FROM python:3.11-slim

WORKDIR /app

COPY requirements.txt ./
RUN pip install --no-cache-dir -r requirements.txt

COPY proxy ./proxy

ENV PROXY_DB_PATH=/data/proxy.db
ENV PROXY_CONF_DIR=/data/mitmproxy

EXPOSE 8080

CMD ["mitmdump", "--mode", "regular", "--listen-host", "0.0.0.0", "--listen-port", "8080", "--set", "confdir=/data/mitmproxy", "-s", "/app/proxy/addon.py"]
