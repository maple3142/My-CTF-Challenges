FROM node:16

RUN apt-get update \
    && apt-get install -y wget gnupg \
    && wget -q -O - https://dl-ssl.google.com/linux/linux_signing_key.pub | apt-key add - \
    && sh -c 'echo "deb [arch=amd64] http://dl.google.com/linux/chrome/deb/ stable main" >> /etc/apt/sources.list.d/google.list' \
    && apt-get update \
    && apt-get install -y libxss1 google-chrome-stable \
      --no-install-recommends \
    && rm -rf /var/lib/apt/lists/*

RUN mkdir /bot/
WORKDIR /bot/
COPY package.json .
RUN PUPPETEER_SKIP_CHROMIUM_DOWNLOAD=true npm i
COPY bot.js .
USER node
CMD ["node", "bot.js"]
