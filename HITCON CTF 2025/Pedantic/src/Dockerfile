FROM python:3.13-slim AS base

WORKDIR /app
RUN pip install fastecdsa
COPY server.py run

FROM pwn.red/jail
COPY --from=base / /srv
ENV JAIL_TIME=300 JAIL_MEM=50M JAIL_CPU=1000 JAIL_ENV_PATH=/usr/local/sbin:/usr/local/bin:/usr/sbin:/usr/bin:/sbin:/bin
