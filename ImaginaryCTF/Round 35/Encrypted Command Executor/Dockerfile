FROM python:3

RUN apt-get update && apt-get install socat -y
RUN python3 -m pip install pycryptodome
RUN mkdir /app

WORKDIR /app
COPY server.py /app

RUN useradd -ms /bin/bash ctf

EXPOSE 3000
CMD ["socat", "TCP-LISTEN:3000,reuseaddr,fork", "EXEC:python3 server.py,stderr,su=ctf"]
