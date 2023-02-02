FROM python:3.10-slim-bullseye

RUN pip install flask gunicorn[gevent]

WORKDIR /app
COPY app.py api.py ./

RUN echo "#!/bin/sh" >> run.sh && \
    echo "gunicorn -k gevent --keep-alive 1 --bind 0.0.0.0:7777 api:app &" >> run.sh && \
    echo "gunicorn -k gevent --keep-alive 1 --bind 0.0.0.0:8888 app:app" >> run.sh && \
    chmod +x run.sh

EXPOSE 8888
ENTRYPOINT ["./run.sh"]
