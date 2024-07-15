FROM debian:bookworm-slim

RUN apt-get update && \
    apt-get install -y tini ca-certificates curl unzip && \
    apt-get clean && \
    rm -rf /var/lib/apt/lists/*
WORKDIR /workdir

ARG RCLONE_VERSION=v1.67.0
ARG RCLONE_NAME=rclone-$RCLONE_VERSION-linux-amd64
ARG RCLONE_HASH=07c23d21a94d70113d949253478e13261c54d14d72023bb14d96a8da5f3e7722

RUN curl https://downloads.rclone.org/$RCLONE_VERSION/$RCLONE_NAME.zip -o rclone.zip && \
    echo $RCLONE_HASH rclone.zip | sha256sum -c && \
    unzip rclone.zip && \
    mv $RCLONE_NAME/rclone /usr/bin

COPY ./readflag /readflag
RUN chmod 111 /readflag

RUN useradd -ms /bin/bash ctf
USER ctf

ENTRYPOINT ["tini", "--"]
CMD rclone rcd --rc-addr 0.0.0.0:5572 --rc-web-gui --rc-user $SECRET --rc-pass $SECRET --rc-web-gui-no-open-browser
