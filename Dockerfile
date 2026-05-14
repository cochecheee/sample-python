# syntax=docker/dockerfile:1.7
# Container build for the vulnerable sample app. Used by V2.2 CD pipeline
# to deploy a staging instance that V2.3 ZAP DAST scans against.
#
# Pinned to Python 3.9 because Flask 1.0 imports `collections.MutableMapping`
# which was removed in Python 3.10+ (moved to collections.abc). Using an
# end-of-life Python image is intentional — also amplifies the Trivy/Safety
# finding surface that this sample is meant to demonstrate.
FROM python:3.9-slim

ENV PYTHONUNBUFFERED=1 PYTHONDONTWRITEBYTECODE=1
WORKDIR /app

COPY requirements.txt ./
RUN pip install --no-cache-dir -r requirements.txt

COPY app.py ./

EXPOSE 5000

HEALTHCHECK --interval=30s --timeout=5s --retries=3 \
  CMD python -c "import urllib.request, sys; sys.exit(0 if urllib.request.urlopen('http://127.0.0.1:5000/health', timeout=3).status == 200 else 1)"

CMD ["python", "app.py"]
