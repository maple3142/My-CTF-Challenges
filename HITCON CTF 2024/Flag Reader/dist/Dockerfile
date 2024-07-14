FROM python:3.12-alpine as base

WORKDIR /app
COPY server.py run

FROM pwn.red/jail
COPY --from=base / /srv
ENV JAIL_TIME=15 JAIL_MEM=20M JAIL_TMP_SIZE=1M
