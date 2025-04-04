FROM pwn.red/jail
COPY --from=python:3.13-alpine / /srv
COPY server.py /srv/app/run
ENV JAIL_MEM=10M
