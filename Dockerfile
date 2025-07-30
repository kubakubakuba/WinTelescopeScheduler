FROM python:3.9-slim

WORKDIR /app

RUN mkdir -p /app/data

COPY requirements.txt requirements.txt
RUN pip3 install -r requirements.txt

COPY . .

# Create data directory and set permissions
RUN mkdir -p data && chmod 777 data

EXPOSE 5000

CMD ["gunicorn", "--config", "gunicorn.conf.py", "app:app"]
