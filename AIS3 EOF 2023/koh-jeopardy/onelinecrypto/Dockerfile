FROM python:3.10

RUN apt-get update && apt-get install socat -y
RUN pip install pycryptodome fastecdsa

WORKDIR /app
COPY server.py .

RUN useradd -ms /bin/bash ctf
USER ctf
EXPOSE 10011
ENTRYPOINT ["socat", "TCP-LISTEN:10011,fork,reuseaddr", "EXEC:'python server.py',stderr"]
