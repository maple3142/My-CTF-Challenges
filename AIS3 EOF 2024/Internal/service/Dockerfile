FROM python:3.12-alpine

RUN apk add --no-cache tini

WORKDIR /home/guest
COPY ./share/server.py .

USER guest
ENTRYPOINT ["/sbin/tini", "--"]
CMD ["python3", "server.py"]
