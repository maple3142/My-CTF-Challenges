FROM node:22-alpine

WORKDIR /app
COPY start.sh app.js note.js purify.js viewer.js viewer.html ./

RUN adduser -D ctf
USER ctf

CMD ["/app/start.sh"]
