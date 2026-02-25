@echo off
chcp 65001 >nul 2>&1

echo.
echo ========================================
echo  gcli2api - Local Development Setup
echo ========================================
echo.

REM Step 1: Activate virtual environment
echo [1/4] Activating virtual environment...
if exist ".venv\Scripts\activate.bat" (
    call .venv\Scripts\activate.bat
    echo [OK] Virtual environment activated
) else (
    echo [ERROR] Virtual environment not found! Run "uv venv" first.
    pause
    exit /b 1
)

REM Step 2: Sync dependencies
echo.
echo [2/4] Syncing dependencies...
where uv >nul 2>&1
if %errorlevel% equ 0 (
    uv sync
) else (
    pip install -r requirements.txt
)
if %errorlevel% neq 0 (
    echo [ERROR] Failed to sync dependencies!
    pause
    exit /b 1
)
echo [OK] Dependencies synced

REM Step 3: Load .env environment variables
echo.
echo [3/4] Loading environment variables...
if exist ".env" (
    for /f "usebackq tokens=* delims=" %%a in (".env") do (
        set "line=%%a"
        setlocal enabledelayedexpansion
        if not "!line!"=="" if not "!line:~0,1!"=="#" (
            endlocal
            set "%%a"
        ) else (
            endlocal
        )
    )
    echo [OK] Environment variables loaded from .env
) else (
    echo [SKIP] No .env file found, skipping
)

REM Step 4: Start the server
echo.
echo [4/4] Starting gcli2api server...
echo.
echo ========================================
echo  Server is starting...
echo ========================================
echo.
python web.py
pause
