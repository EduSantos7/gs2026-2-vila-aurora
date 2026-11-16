FROM python:3.12-slim
ENV PYTHONUNBUFFERED=1 PYTHONDONTWRITEBYTECODE=1
WORKDIR /srv
COPY requirements.txt .
RUN pip install --no-cache-dir -r requirements.txt \
 && useradd -u 10001 -m app && mkdir -p /buffer /state /logs && chown app:app /buffer /state /logs
COPY app ./app
USER app
