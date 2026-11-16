# Container de ferramentas: gera PKI e segredos sem instalar nada no Windows/WSL
FROM python:3.12-alpine
RUN apk add --no-cache openssl bash \
 && pip install --no-cache-dir cryptography==43.0.3 werkzeug==3.0.6
WORKDIR /w
