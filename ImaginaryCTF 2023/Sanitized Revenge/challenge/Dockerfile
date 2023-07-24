FROM node:20-bookworm-slim

RUN apt-get update && \
apt-get install -y chromium dumb-init && \
rm -rf /var/lib/apt/lists/*

ENV NODE_ENV=production \
PUPPETEER_SKIP_CHROMIUM_DOWNLOAD=true \
PUPPETEER_EXECUTABLE_PATH=/usr/bin/chromium

VOLUME /home/ctf
VOLUME /run

RUN addgroup ctf && \
adduser --disabled-password --gecos "" --ingroup ctf ctf

RUN mkdir /home/ctf/app
WORKDIR /home/ctf/app
COPY package.json yarn.lock /home/ctf/app

RUN chown -R ctf:ctf .
USER ctf
RUN yarn && mkdir -p /home/ctf/Downloads

COPY src /home/ctf/app

VOLUME /tmp

EXPOSE 3000

ENV FLAG=ictf{no_more_cheese_using_%2f..%2f_so_you_must_bypass_dompurify}

ENTRYPOINT ["/usr/bin/dumb-init", "--"]
CMD ["node", "/home/ctf/app/app.js"]
