@echo off

REM SGI Server Docker Deployment Script for Windows

echo 🚀 Starting SGI Server Docker Deployment...

REM Check if Docker is installed
docker --version >nul 2>&1
if %errorlevel% neq 0 (
    echo ❌ Docker is not installed. Please install Docker Desktop first.
    pause
    exit /b 1
)

REM Check if Docker Compose is installed
docker-compose --version >nul 2>&1
if %errorlevel% neq 0 (
    echo ❌ Docker Compose is not installed. Please install Docker Compose first.
    pause
    exit /b 1
)

REM Create necessary directories
echo 📁 Creating necessary directories...
if not exist "database" mkdir database
if not exist "logs" mkdir logs

REM Build and start the containers
echo 🔨 Building Docker image...
docker-compose build

if %errorlevel% neq 0 (
    echo ❌ Failed to build Docker image.
    pause
    exit /b 1
)

echo 🌟 Starting SGI Server...
docker-compose up -d

if %errorlevel% neq 0 (
    echo ❌ Failed to start SGI Server.
    pause
    exit /b 1
)

REM Wait for the service to be ready
echo ⏳ Waiting for SGI Server to be ready...
timeout /t 10 /nobreak >nul

REM Check if the service is running
docker-compose ps | findstr "Up" >nul 2>&1
if %errorlevel% equ 0 (
    echo ✅ SGI Server is running successfully!
    echo 🌐 Access the application at: http://localhost:5000
    echo 📊 To view logs: docker-compose logs -f sgi-server
    echo 🛑 To stop: docker-compose down
) else (
    echo ❌ Failed to start SGI Server. Check logs with: docker-compose logs
    pause
    exit /b 1
)

pause