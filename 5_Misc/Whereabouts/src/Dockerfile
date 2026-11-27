FROM python:3.12-slim

# non-root
RUN useradd -m -u 10001 ctf
WORKDIR /app

COPY app.py ./
COPY public/ ./public/


USER ctf
EXPOSE 25000
CMD ["python3", "-u", "app.py", "--host", "0.0.0.0", "--port", "25000"]
