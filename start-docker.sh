#!/bin/bash

# SGI Server Docker Deployment Script

echo "🚀 Starting SGI Server Docker Deployment..."

# Check if Docker is installed
if ! command -v docker &> /dev/null; then
    echo "❌ Docker is not installed. Please install Docker first."
    exit 1
fi

# Check if Docker Compose is installed
if ! command -v docker-compose &> /dev/null; then
    echo "❌ Docker Compose is not installed. Please install Docker Compose first."
    exit 1
fi

# Create necessary directories
echo "📁 Creating necessary directories..."
mkdir -p ./database
mkdir -p ./logs

# Set permissions
chmod 755 ./database
chmod 755 ./logs

# Build and start the containers
echo "🔨 Building Docker image..."
docker-compose build

echo "🌟 Starting SGI Server..."
docker-compose up -d

# Wait for the service to be ready
echo "⏳ Waiting for SGI Server to be ready..."
sleep 10

# Check if the service is running
if docker-compose ps | grep -q "Up"; then
    echo "✅ SGI Server is running successfully!"
    echo "🌐 Access the application at: http://localhost:5000"
    echo "📊 To view logs: docker-compose logs -f sgi-server"
    echo "🛑 To stop: docker-compose down"
else
    echo "❌ Failed to start SGI Server. Check logs with: docker-compose logs"
    exit 1
fi