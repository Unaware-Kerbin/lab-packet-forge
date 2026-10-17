FROM python:3.12-slim-bookworm

RUN apt-get update && apt-get install -y --no-install-recommends \
    libpcap0.8 \
    iproute2 \
    iputils-ping \
    tcpdump \
    && rm -rf /var/lib/apt/lists/*

# Gateway killswitch (default on): stop TX if probe target(s) unreachable for 120s.
# FORGE_GATEWAY_KILL_TARGET empty/auto = container default route GW (clab mgmt).
# Set to DUT/lab GW (e.g. 10.1.0.1) for useful lab protection. Secondary=auto adds eth1 nexthop.
ENV FORGE_GATEWAY_KILL=1
ENV FORGE_GATEWAY_KILL_TIMEOUT_S=120
ENV FORGE_GATEWAY_KILL_TARGET=
ENV FORGE_GATEWAY_KILL_SECONDARY=
ENV FORGE_LAB_GATEWAY=

WORKDIR /opt/trafficgen
COPY requirements.txt .
RUN pip install --no-cache-dir -r requirements.txt

COPY app ./app
COPY scripts ./scripts

ENV FORGE_HOST=0.0.0.0
ENV FORGE_PORT=8080
ENV FORGE_IFACE=eth1
ENV PYTHONUNBUFFERED=1

EXPOSE 8080
CMD ["uvicorn", "app.main:app", "--host", "0.0.0.0", "--port", "8080"]
