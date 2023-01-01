FROM ubuntu:22.04 AS builder

RUN apt-get update && apt-get install gcc -y && rm -rf /var/cache/apt/archives /var/lib/apt/lists/*
COPY src /src
WORKDIR /src
RUN gcc main.c -Wall -o main -z now -O2

FROM ubuntu:22.04 AS base

FROM pwn.red/jail
COPY --from=base / /srv
ENV JAIL_PORT=1225
COPY --from=builder /src/main /srv/app/run
COPY --from=builder /src/flag.txt /srv/app/flag.txt
