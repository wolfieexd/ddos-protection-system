FROM python:3.11-slim
WORKDIR /app
COPY requirements.txt .
RUN pip install --no-cache-dir -r requirements.txt
COPY . .
RUN useradd -m appuser && chown -R appuser:appuser /app
USER appuser
EXPOSE 8000
CMD ["gunicorn", "--chdir", "web-app", "-w", "4", "-b", "0.0.0.0:8000", "--access-logfile", "-", "app:app"]
