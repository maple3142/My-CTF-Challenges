FROM python:3.11-alpine as builder

RUN apk add --no-cache build-base
COPY csidh-latest.tar.xz /tmp
RUN tar -xf /tmp/csidh-latest.tar.xz -C /tmp
WORKDIR /tmp/csidh-20210627
RUN make libcsidh.so

FROM python:3.11-alpine

RUN apk add --no-cache socat

WORKDIR /app
COPY --from=builder /tmp/csidh-20210627/libcsidh.so /app
COPY server.py flag.txt /app

USER nobody
CMD ["socat", "TCP-LISTEN:1337,reuseaddr,fork", "EXEC:python server.py"]
