FROM ubuntu:22.04 AS base

FROM pwn.red/jail
COPY --from=base / /srv
ENV JAIL_PORT=1234
COPY ./src/chall /srv/app/run
COPY ./flag.txt /srv/app/flag.txt
