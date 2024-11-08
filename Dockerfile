FROM python:3.9.20-alpine3.19
WORKDIR /app
RUN pip install Flask
COPY . .
EXPOSE 5000
CMD [ "python3", "/app/main.py" ]