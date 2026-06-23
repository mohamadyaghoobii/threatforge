FROM python:3.12-slim

WORKDIR /app

RUN apt-get update && apt-get install -y git && rm -rf /var/lib/apt/lists/*

COPY packages/rule_engine /app/packages/rule_engine
COPY apps/api /app/apps/api
COPY configs /app/configs

RUN pip install --no-cache-dir -e /app/packages/rule_engine && pip install --no-cache-dir -e /app/apps/api

WORKDIR /app/apps/api

EXPOSE 8000

CMD ["uvicorn", "app.main:app", "--host", "0.0.0.0", "--port", "8000"]
