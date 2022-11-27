FROM debian:bullseye

RUN useradd -ms /bin/bash ctf
RUN apt-get update && apt-get install wget unzip socat openssl -y && rm -rf /var/lib/apt/lists/*

# try to execute /printflag to get flag
COPY printflag /printflag
RUN chmod 111 /printflag

USER ctf
WORKDIR /tmp
RUN wget https://download.jboss.org/jbosstools/vscode/stable/lemminx-binary/0.19.1-541/lemminx-linux.zip
RUN echo '0c6d830398926421a28dbfc716ad8bc6b27edf67ae67afd3efa97432b5715922 lemminx-linux.zip' | sha256sum -c
RUN unzip lemminx-linux.zip && rm lemminx-linux.zip
RUN printf '#!/bin/sh\ntimeout 10 ./lemminx-linux\n' > run.sh && chmod +x run.sh

EXPOSE 7777
ARG TIMEOUT
CMD mkdir /home/ctf/$(openssl rand -hex 16) && mv /tmp/* /home/ctf/* && cd /home/ctf/* && timeout ${TIMEOUT} socat TCP-LISTEN:7777,fork,reuseaddr EXEC:'./run.sh',stderr
