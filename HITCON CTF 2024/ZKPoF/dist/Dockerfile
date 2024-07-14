FROM python:3.12-alpine as base

WORKDIR /app
RUN pip install pycryptodome
COPY server.py run

FROM pwn.red/jail
COPY --from=base / /srv
ENV JAIL_TIME=60 JAIL_MEM=10M JAIL_CPU=1000
