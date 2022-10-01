FROM debian:bullseye AS base

RUN apt-get update && apt-get install qemu-system-x86 -y && rm -rf /var/cache/apt/archives /var/lib/apt/lists/*

FROM pwn.red/jail
COPY --from=base / /srv
ENV JAIL_MEM=128M
ENV JAIL_TIME=120
ENV JAIL_PORT=1235
ENV JAIL_CPU=500
ENV JAIL_POW=3000
COPY vm /srv/app/vm
COPY run.sh /srv/app/run
