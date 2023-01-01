FROM alpine:3

RUN apk add python3 py3-pycryptodome socat --no-cache
RUN mkdir /app

WORKDIR /app
COPY . /app

CMD ["socat", "TCP-LISTEN:1337,reuseaddr,fork", "EXEC:python3 server.py"]
