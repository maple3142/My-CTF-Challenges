FROM alpine:3 AS app

RUN apk add --no-cache openjdk17 python3 socat
RUN mkdir /app

WORKDIR /app
COPY server.py .
COPY flag.txt .

RUN adduser -S ctf
USER ctf
CMD ["socat", "TCP-LISTEN:1234,fork,reuseaddr", "EXEC:'python3 server.py',stderr"]
