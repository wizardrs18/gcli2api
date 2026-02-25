"""
Configuration constants for the Geminicli2api proxy server.
All configuration is read from environment variables (.env file).
"""

import os

# Client Configuration

# 需要自动封禁的错误码 (默认值，可通过环境变量覆盖)
AUTO_BAN_ERROR_CODES = [403]


# Configuration getters - all async (signatures kept for compatibility with 50+ callers)

async def get_auto_ban_enabled() -> bool:
    """Get auto ban enabled setting."""
    env_value = os.getenv("AUTO_BAN", "")
    return env_value.lower() in ("true", "1", "yes", "on") if env_value else False


async def get_auto_ban_error_codes() -> list:
    """Get auto ban error codes."""
    env_value = os.getenv("AUTO_BAN_ERROR_CODES")
    if env_value:
        try:
            return [int(code.strip()) for code in env_value.split(",") if code.strip()]
        except ValueError:
            pass
    return AUTO_BAN_ERROR_CODES


async def get_retry_429_max_retries() -> int:
    """Get max retries for 429 errors."""
    env_value = os.getenv("RETRY_429_MAX_RETRIES")
    if env_value:
        try:
            return int(env_value)
        except ValueError:
            pass
    return 5


async def get_retry_429_enabled() -> bool:
    """Get 429 retry enabled setting."""
    env_value = os.getenv("RETRY_429_ENABLED")
    if env_value:
        return env_value.lower() in ("true", "1", "yes", "on")
    return True


async def get_retry_429_interval() -> float:
    """Get 429 retry interval in seconds."""
    env_value = os.getenv("RETRY_429_INTERVAL")
    if env_value:
        try:
            return float(env_value)
        except ValueError:
            pass
    return 0.1


async def get_anti_truncation_max_attempts() -> int:
    """Get maximum attempts for anti-truncation continuation."""
    env_value = os.getenv("ANTI_TRUNCATION_MAX_ATTEMPTS")
    if env_value:
        try:
            return int(env_value)
        except ValueError:
            pass
    return 3


# Server Configuration
async def get_server_host() -> str:
    """Get server host setting."""
    return os.getenv("HOST", "0.0.0.0")


async def get_server_port() -> int:
    """Get server port setting."""
    env_value = os.getenv("PORT")
    if env_value:
        try:
            return int(env_value)
        except ValueError:
            pass
    return 7861


async def get_api_password() -> str:
    """Get API password setting for chat endpoints."""
    api_password = os.getenv("API_PASSWORD")
    if api_password is not None:
        return api_password
    return os.getenv("PASSWORD", "pwd")


async def get_panel_password() -> str:
    """Get panel password setting for web interface."""
    panel_password = os.getenv("PANEL_PASSWORD")
    if panel_password is not None:
        return panel_password
    return os.getenv("PASSWORD", "pwd")


async def get_server_password() -> str:
    """Get server password setting (deprecated, use get_api_password or get_panel_password)."""
    return os.getenv("PASSWORD", "pwd")


async def get_credentials_dir() -> str:
    """Get credentials directory setting."""
    return os.getenv("CREDENTIALS_DIR", "./creds")


async def get_code_assist_endpoint() -> str:
    """Get Code Assist endpoint setting."""
    return os.getenv("CODE_ASSIST_ENDPOINT", "https://cloudcode-pa.googleapis.com")


async def get_compatibility_mode_enabled() -> bool:
    """Get compatibility mode setting."""
    env_value = os.getenv("COMPATIBILITY_MODE")
    if env_value:
        return env_value.lower() in ("true", "1", "yes", "on")
    return False


async def get_return_thoughts_to_frontend() -> bool:
    """Get return thoughts to frontend setting."""
    env_value = os.getenv("RETURN_THOUGHTS_TO_FRONTEND")
    if env_value:
        return env_value.lower() in ("true", "1", "yes", "on")
    return True


async def get_antigravity_stream2nostream() -> bool:
    """Get use stream for non-stream setting."""
    env_value = os.getenv("ANTIGRAVITY_STREAM2NOSTREAM")
    if env_value:
        return env_value.lower() in ("true", "1", "yes", "on")
    return True


async def get_oauth_proxy_url() -> str:
    """Get OAuth proxy URL setting."""
    return os.getenv("OAUTH_PROXY_URL", "https://oauth2.googleapis.com")


async def get_googleapis_proxy_url() -> str:
    """Get Google APIs proxy URL setting."""
    return os.getenv("GOOGLEAPIS_PROXY_URL", "https://www.googleapis.com")


async def get_resource_manager_api_url() -> str:
    """Get Google Cloud Resource Manager API URL setting."""
    return os.getenv("RESOURCE_MANAGER_API_URL", "https://cloudresourcemanager.googleapis.com")


async def get_service_usage_api_url() -> str:
    """Get Google Cloud Service Usage API URL setting."""
    return os.getenv("SERVICE_USAGE_API_URL", "https://serviceusage.googleapis.com")


async def get_antigravity_api_url() -> str:
    """Get Antigravity API URL setting."""
    return os.getenv("ANTIGRAVITY_API_URL", "https://daily-cloudcode-pa.sandbox.googleapis.com")


async def get_novel_backend_url() -> str:
    """Get novel backend URL setting."""
    return os.getenv("NOVEL_BACKEND_URL", "http://localhost:8000")


async def get_novel_admin_api_key() -> str:
    """Get novel backend admin API key."""
    return os.getenv("NOVEL_ADMIN_API_KEY", "change-me-in-production")
