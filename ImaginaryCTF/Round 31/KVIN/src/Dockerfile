FROM node:18-alpine AS app

WORKDIR /app
COPY package.json yarn.lock .
RUN yarn

FROM pwn.red/jail
COPY --from=app / /srv
COPY ./index.js /srv/app/run
ENV JAIL_MEM=64M JAIL_PIDS=10
