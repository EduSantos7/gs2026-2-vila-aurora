# ATENÇÃO: aplicação PROPOSITALMENTE VULNERÁVEL para reprodução do INC-VA-0712.
# Rodar SOMENTE no laboratório isolado (perfil "legado", publicado só em 127.0.0.1).
FROM python:3.12-slim
ENV PYTHONUNBUFFERED=1
WORKDIR /srv
COPY requirements.txt .
RUN pip install --no-cache-dir -r requirements.txt
COPY app.py .
CMD ["gunicorn", "-b", "0.0.0.0:8000", "-w", "2", "--access-logfile", "-", "app:app"]
