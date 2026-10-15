FROM python:3.11-slim
WORKDIR /app
# Pinned: app.py overrides werkzeug's request handler to hide its Server header.
RUN pip install --no-cache-dir flask==3.1.3 werkzeug==3.1.9 && useradd --uid 10001 --no-create-home canary
COPY app.py .
# Non-root; the host log dir (logs/canary) is chowned to 10001 by scripts/deploy.sh.
USER 10001
EXPOSE 8080
CMD ["python", "app.py"]
