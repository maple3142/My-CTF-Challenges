FROM sagemath/sagemath:10.3 as base

FROM sagemath/sagemath:10.3 as work
WORKDIR /app
COPY ./server.sage ./
RUN sage --preparse ./server.sage

FROM pwn.red/jail
COPY --from=base / /srv
RUN mkdir /srv/app && printf '#!/bin/sh\nsage ./server.sage.py\n' > /srv/app/run && chmod +x /srv/app/run
COPY --from=work /app/server.sage.py /srv/app
ENV JAIL_MEM=128M JAIL_PIDS=30 JAIL_ENV_HOME=/tmp JAIL_TMP_SIZE=1M JAIL_CPU=1000
