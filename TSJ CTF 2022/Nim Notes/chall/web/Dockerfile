FROM nimlang/nim:1.6.0-alpine

RUN apk add nginx
RUN nimble install jester@0.5.0 -y
RUN nimble install redis@0.3.0 -y
RUN mkdir /app
WORKDIR /app
COPY app.nim .
RUN nim c -d:release -d:ssl app
COPY public public
COPY templates templates
COPY default.conf /etc/nginx/http.d/default.conf
COPY start.sh /start.sh

CMD ["/start.sh"]
