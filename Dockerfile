FROM python:3.12-slim
WORKDIR /app
COPY backend/requirements.txt ./requirements.txt
RUN pip install --no-cache-dir -r requirements.txt
COPY backend ./backend
ENV PORT=5000
EXPOSE 5000
CMD ["python", "backend/app.py"]
