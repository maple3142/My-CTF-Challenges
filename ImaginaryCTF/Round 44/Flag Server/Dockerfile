FROM python:3.11-slim-bookworm

RUN pip install bottle gunicorn gunicorn[gevent] playwright
RUN playwright install-deps
RUN playwright install chromium
WORKDIR /app
COPY app.py .
COPY Dockerfile .

CMD [ "gunicorn", "-k", "gevent", "--bind", "0.0.0.0:3000", "app"]
