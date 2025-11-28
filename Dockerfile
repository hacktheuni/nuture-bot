FROM python:3.11-slim

# Set working directory in the container
WORKDIR /app

# Copy the requirements file and install dependencies
# This step is cached if requirements.txt doesn't change, speeding up subsequent builds
COPY requirements.txt .
RUN pip install --no-cache-dir -r requirements.txt

# Copy the rest of the application code
COPY . .

# Expose the port your application runs on (default for Uvicorn)
EXPOSE 8000

# Command to run the application using Uvicorn (recommended for production)
CMD ["uvicorn", "app.main:app", "--host", "0.0.0.0", "--port", "8001"]