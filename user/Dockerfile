FROM python:3.11-slim
ENV PYTHONDONTWRITEBYTECODE=1 \
PYTHONUNBUFFERED=1 \
PIP_NO_CACHE_DIR=1


# non-root
RUN useradd -m appuser
WORKDIR /app


COPY requirements.txt .
RUN pip install -r requirements.txt


COPY . .
USER appuser
EXPOSE 5000
ENV FLASK_APP=app:create_app
CMD ["gunicorn", "-w", "1", "-b", "0.0.0.0:5000", "--timeout", "120", "app:create_app()"]