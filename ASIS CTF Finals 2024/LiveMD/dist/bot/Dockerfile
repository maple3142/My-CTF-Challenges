FROM node:22-alpine

RUN apk add chromium dumb-init

RUN mkdir /app
WORKDIR /app
COPY package.json yarn.lock /app/
RUN PUPPETEER_SKIP_CHROMIUM_DOWNLOAD=true yarn

RUN adduser -D -u 1001 bot && \
    mkdir -p /home/bot && \
    chown -R bot:bot /home/bot && \
    chmod -R 755 /home/bot

COPY . .
USER bot
ENV PUPPETEER_EXECUTABLE_PATH=/usr/bin/chromium-browser

# idk why puppeteer doesn't handle SIGTERM properly despite "handleSIGTERM: true"...
ENTRYPOINT ["/usr/bin/dumb-init", "--rewrite", "15:2", "--"]
CMD ["node", "app.js"]
