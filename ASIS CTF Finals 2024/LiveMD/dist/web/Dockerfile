# syntax=docker/dockerfile:1.7-labs
FROM node:22-bookworm-slim

COPY package.json yarn.lock /app/
WORKDIR /app
RUN yarn install
COPY --parents *.vue *.ts *.json pages components /app/
RUN yarn build

CMD ["/app/.output/server/index.mjs"]
