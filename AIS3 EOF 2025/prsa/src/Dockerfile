FROM python:3.12-alpine

WORKDIR /app
RUN apk add socat --no-cache
RUN pip install pycryptodome
COPY server.py .

CMD ["socat", "TCP-LISTEN:1337,reuseaddr,fork", "EXEC:python3 server.py"]
