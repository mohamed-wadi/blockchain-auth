FROM python:3.11-slim

WORKDIR /app

# Install system dependencies for qrcode/Pillow
RUN apt-get update && apt-get install -y \
    build-essential \
    libjpeg-dev \
    zlib1g-dev \
    && rm -rf /var/lib/apt/lists/*

COPY requirements.txt .
RUN pip install --no-cache-dir -r requirements.txt

COPY . .

# Expose port 7860 (Hugging Face default)
EXPOSE 7860

# Command to run the app
CMD ["gunicorn", "app:app", "--worker-class", "eventlet", "--bind", "0.0.0.0:7860"]
