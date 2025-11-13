FROM python:3.10-slim

WORKDIR /app

# Copy app & install deps
COPY requirements.txt .
RUN pip install --no-cache-dir -r requirements.txt

COPY . /app

EXPOSE 7003

# Jalankan Flask app
CMD ["python", "backend.py"]
