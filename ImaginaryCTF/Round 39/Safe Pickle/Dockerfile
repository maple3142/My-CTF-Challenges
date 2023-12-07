FROM python:3.11-alpine AS app

RUN pip install picklescan==0.0.12

FROM pwn.red/jail
COPY --from=app / /srv
COPY ./server.py /srv/app/run
ENV JAIL_MEM=32M
