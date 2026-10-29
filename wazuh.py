from __future__ import annotations

import os
from typing import Any
from urllib.parse import urljoin

import httpx


class WazuhError(RuntimeError):
    """Readable Wazuh connection/authentication error."""


class WazuhClient:
    def __init__(self) -> None:
        self.base_url = os.getenv("WAZUH_API_URL", "").strip().rstrip("/")
        self.username = os.getenv("WAZUH_USERNAME", "").strip()
        self.password = os.getenv("WAZUH_PASSWORD", "")
        self.verify_ssl = os.getenv("WAZUH_VERIFY_SSL", "true").lower() == "true"
        self.timeout = float(os.getenv("WAZUH_TIMEOUT", "12"))

    def _config_check(self) -> None:
        missing = []
        if not self.base_url:
            missing.append("WAZUH_API_URL")
        if not self.username:
            missing.append("WAZUH_USERNAME")
        if not self.password:
            missing.append("WAZUH_PASSWORD")
        if missing:
            raise WazuhError("Missing configuration: " + ", ".join(missing) + ". Set these in your .env file.")

    def _token(self) -> str:
        self._config_check()
        url = f"{self.base_url}/security/user/authenticate?raw=true"
        try:
            with httpx.Client(verify=self.verify_ssl, timeout=self.timeout) as client:
                response = client.post(url, auth=(self.username, self.password))
                response.raise_for_status()
                token = response.text.strip().strip('"')
                if not token:
                    try:
                        token = response.json()["data"]["token"]
                    except (ValueError, KeyError, TypeError):
                        pass
                if not token:
                    raise WazuhError("Wazuh API authentication returned an empty token.")
                return token
        except httpx.HTTPStatusError as exc:
            raise WazuhError(f"Authentication failed with HTTP {exc.response.status_code}. Check the Wazuh API credentials and URL.") from exc
        except httpx.RequestError as exc:
            raise WazuhError(f"Cannot reach the Wazuh API at {self.base_url}. Check the address, port, firewall, and TLS settings.") from exc

    def _get(self, path: str, params: dict[str, Any] | None = None) -> dict[str, Any]:
        token = self._token()
        url = f"{self.base_url}/{path.lstrip('/')}"
        try:
            with httpx.Client(verify=self.verify_ssl, timeout=self.timeout) as client:
                response = client.get(url, headers={"Authorization": f"Bearer {token}"}, params=params)
                response.raise_for_status()
                body = response.json()
                if not isinstance(body, dict):
                    raise WazuhError("Wazuh returned an unexpected response format.")
                return body
        except httpx.HTTPStatusError as exc:
            raise WazuhError(f"Wazuh API returned HTTP {exc.response.status_code} for {path}.") from exc
        except httpx.RequestError as exc:
            raise WazuhError(f"Network error while requesting {path}: {exc.__class__.__name__}.") from exc
        except ValueError as exc:
            raise WazuhError("Wazuh returned invalid JSON.") from exc

    def get_agents(self) -> list[dict[str, Any]]:
        body = self._get("agents", {"limit": 500, "select": "id,name,status,ip,version,os"})
        data = body.get("data", {})
        agents = data.get("affected_items", []) if isinstance(data, dict) else []
        return agents if isinstance(agents, list) else []
