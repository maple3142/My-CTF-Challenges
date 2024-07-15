FROM denoland/deno:1.45.2

EXPOSE 8000

COPY readflag /readflag
RUN chmod 111 /readflag

WORKDIR /app
USER deno
COPY main.ts utils.ts deno.json deno.lock ./
COPY pages/ ./pages/
RUN deno cache --no-lock main.ts

CMD ["task", "start"]
