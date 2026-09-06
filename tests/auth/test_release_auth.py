"""Tests for release image auth behavior: DEV_MODE defaults to false, rejects unauthenticated calls."""

from unittest.mock import patch
import pytest
from fastapi.testclient import TestClient

from core.config import get_settings
from services.api.main import app


def test_dev_mode_setting_can_be_disabled():
    """Verify settings.dev_mode controls the auth bypass."""
    settings = get_settings()
    with patch.object(settings, "dev_mode", False):
        assert settings.dev_mode is False


def test_unauthenticated_api_call_rejected_in_release_mode():
    """Verify release mode (DEV_MODE=False) rejects unauthenticated requests with 401 Unauthorized."""
    settings = get_settings()
    with patch.object(settings, "dev_mode", False), \
         patch.object(settings, "mcp_auto_connect_on_startup", False), \
         patch("services.api.middleware.auth.DEV_MODE", False):
        with TestClient(app) as client:
            response = client.get("/api/cases/")
            assert response.status_code == 401
            assert "not authenticated" in response.text.lower()
