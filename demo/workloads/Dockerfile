FROM python:3.11.14-slim-bookworm
ENV PYTHONUNBUFFERED=1 PYTHONDONTWRITEBYTECODE=1
WORKDIR /app
COPY pod_reader.py /app/pod_reader.py
USER 10001:10001
EXPOSE 8080
CMD ["python","/app/pod_reader.py"]
