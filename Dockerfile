FROM python:3.12-slim
WORKDIR /app
ENV PYTHONDONTWRITEBYTECODE=1 PYTHONUNBUFFERED=1
COPY requirements-servidor.txt ./
RUN pip install --no-cache-dir -r requirements-servidor.txt
COPY servidor.py servidor_v98.py start_render.py ./
CMD ["python", "start_render.py"]
