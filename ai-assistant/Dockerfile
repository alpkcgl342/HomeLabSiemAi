FROM python:3.12-slim

WORKDIR /app
COPY requirements.txt .
RUN pip install --no-cache-dir -r requirements.txt

COPY pyproject.toml .
COPY homesiem ./homesiem
RUN pip install --no-cache-dir --no-deps . \
 && useradd --create-home --uid 1000 analyst
USER analyst

ENTRYPOINT ["homesiem"]
CMD ["--help"]
