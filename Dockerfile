FROM python:3.10-slim
ENV FLASK_DEBUG=false \
    PYTHONDONTWRITEBYTECODE=1 \
    PYTHONUNBUFFERED=1 \
    PYTHONIOENCODING="utf-8"
WORKDIR /app
RUN apt update -y \
    && apt install --no-install-recommends -y build-essential git \
    && pip install poetry \
    && poetry config virtualenvs.create false
COPY . .
RUN poetry install --no-cache --without dev \
    && apt remove -y build-essential git \
    && useradd -ms /bin/bash threat_db \
    && rm -rf /var/lib/apt/lists/*
EXPOSE 8000
USER threat_db
CMD ["uwsgi", "--http-socket", ":8000", "--uid", "1000", "--wsgi-file", "threat_db/api.py", "--callable", "app", "--master", "--thunder-lock", "--processes", "4"]
