FROM python:3.11-slim
WORKDIR /app
COPY requirements.txt .
RUN pip install --no-cache-dir -r requirements.txt
COPY . .
RUN useradd -m -u 1000 netpulse && chown -R netpulse:netpulse /app
USER netpulse
EXPOSE 5005
ENV PYTHONUNBUFFERED=1
CMD ["gunicorn","--worker-class","eventlet","-w","1","--bind","0.0.0.0:5005","--timeout","120","wsgi:app"]
