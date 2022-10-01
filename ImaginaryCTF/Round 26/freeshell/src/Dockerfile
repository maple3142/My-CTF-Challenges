FROM gcc:bullseye as builder

RUN apt-get update && apt-get install libseccomp-dev -y
WORKDIR /tmp
COPY shell.c .
COPY readflag.c .
COPY Makefile .
RUN make

FROM debian:bullseye-slim

RUN apt-get update && apt-get install socat -y
RUN useradd -ms /bin/bash ctf
RUN mkdir /challenge
WORKDIR /challenge
COPY --from=builder /tmp/shell .
COPY --from=builder /tmp/readflag /
COPY shell.c .
COPY Makefile .
COPY Dockerfile .
RUN chmod -R o-w .
RUN chmod o=x /readflag
RUN chmod o=wx /tmp

USER ctf
EXPOSE 8787
CMD ["socat", "TCP-LISTEN:8787,fork,reuseaddr", "EXEC:'./shell',stderr"]
# docker build . -t freeshell
# docker run --rm -p 8787:8787 freeshell
