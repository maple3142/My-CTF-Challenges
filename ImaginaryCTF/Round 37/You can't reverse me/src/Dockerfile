FROM alpine:3 as builder

RUN apk add --no-cache build-base
WORKDIR /app
COPY checker.c .
RUN gcc checker.c -o checker

FROM alpine:3 as app
WORKDIR /app
COPY --from=builder /app/checker .
RUN chmod 111 checker && \
    printf '#!/bin/sh\nsh\n' > run && \
    chmod +x run && \
    chown -R root:root /app

FROM pwn.red/jail
COPY --from=app / /srv
ENV JAIL_TIME=60 JAIL_TMP_SIZE=1M
