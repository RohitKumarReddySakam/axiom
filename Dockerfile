FROM python:3.12-slim
WORKDIR /app
RUN apt-get update && apt-get upgrade -y && apt-get clean && rm -rf /var/lib/apt/lists/*
COPY requirements.txt .
RUN pip install --no-cache-dir -r requirements.txt
COPY . .
RUN useradd -m -u 1000 analyzer && chown -R analyzer:analyzer /app
USER analyzer
EXPOSE 5002
ENV PYTHONUNBUFFERED=1
CMD ["gunicorn","--worker-class","eventlet","-w","1","--bind","0.0.0.0:5002","--timeout","120","wsgi:app"]
