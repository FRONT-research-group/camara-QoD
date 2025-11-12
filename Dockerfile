FROM python:3.12.10-bullseye

WORKDIR /app

RUN apt-get update && apt-get install -y build-essential && rm -rf /var/lib/apt/lists/*

COPY requirements.txt ./requirements.txt
RUN pip install --no-cache-dir -r requirements.txt

COPY src ./src

EXPOSE 8001

ENV ASSESSIONWITHQOS_URL="http://10.220.2.43:8585/3gpp-as-session-with-qos/v1"
ENV LOG_LEVEL="DEBUG"

CMD ["python3", "src/main.py"]