FROM python:3-bullseye

RUN pip install playwright && \
    playwright install-deps && \
    playwright install chromium
WORKDIR /app
COPY . .

CMD ["python", "server.py"]
