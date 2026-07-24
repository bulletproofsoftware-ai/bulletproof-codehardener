"""
Code Hardener Python SDK

Usage:
    from codehardener import CodeHardener

    ch = CodeHardener(api_key="ch_...")
    scan = ch.scans.create(repository_url="https://github.com/...")
    result = ch.scans.wait_for_completion(scan["id"])
"""

from __future__ import annotations

import time
from typing import Any, Optional

import httpx


class ApiError(Exception):
    """Raised when the API returns an error response."""

    def __init__(self, status_code: int, message: str):
        self.status_code = status_code
        super().__init__(f"HTTP {status_code}: {message}")


class _Resource:
    def __init__(self, client: CodeHardener):
        self._client = client


class ScansApi(_Resource):
    def create(
        self,
        *,
        repository_url: Optional[str] = None,
        project_id: Optional[str] = None,
        profile: str = "standard",
        branch: Optional[str] = None,
        commit_sha: Optional[str] = None,
        scanners: Optional[list[str]] = None,
    ) -> dict[str, Any]:
        body: dict[str, Any] = {"profile": profile}
        if repository_url:
            body["repositoryUrl"] = repository_url
        if project_id:
            body["projectId"] = project_id
        if branch:
            body["branch"] = branch
        if commit_sha:
            body["commitSha"] = commit_sha
        if scanners:
            body["scanners"] = scanners
        return self._client._request("POST", "/api/v1/scans", json=body)

    def get(self, scan_id: str) -> dict[str, Any]:
        return self._client._request("GET", f"/api/v1/scans/{scan_id}")

    def list(
        self,
        *,
        project_id: Optional[str] = None,
        page: int = 1,
        limit: int = 20,
    ) -> dict[str, Any]:
        params: dict[str, Any] = {"page": page, "limit": limit}
        if project_id:
            params["projectId"] = project_id
        return self._client._request("GET", "/api/v1/scans", params=params)

    def wait_for_completion(
        self,
        scan_id: str,
        *,
        poll_interval: float = 3.0,
        timeout: float = 600.0,
    ) -> dict[str, Any]:
        deadline = time.monotonic() + timeout
        while time.monotonic() < deadline:
            scan = self.get(scan_id)
            if scan.get("status") in ("completed", "failed"):
                return scan
            time.sleep(poll_interval)
        raise TimeoutError(f"Scan {scan_id} timed out after {timeout}s")


class FindingsApi(_Resource):
    def list(
        self,
        *,
        scan_id: Optional[str] = None,
        project_id: Optional[str] = None,
        severity: Optional[str] = None,
        page: int = 1,
        limit: int = 50,
    ) -> dict[str, Any]:
        params: dict[str, Any] = {"page": page, "limit": limit}
        if scan_id:
            params["scanId"] = scan_id
        if project_id:
            params["projectId"] = project_id
        if severity:
            params["severity"] = severity
        return self._client._request("GET", "/api/v1/findings", params=params)

    def get(self, finding_id: str) -> dict[str, Any]:
        return self._client._request("GET", f"/api/v1/findings/{finding_id}")


class ProjectsApi(_Resource):
    def create(self, *, name: str, repository_url: Optional[str] = None) -> dict[str, Any]:
        body: dict[str, Any] = {"name": name}
        if repository_url:
            body["repositoryUrl"] = repository_url
        return self._client._request("POST", "/api/v1/projects", json=body)

    def get(self, project_id: str) -> dict[str, Any]:
        return self._client._request("GET", f"/api/v1/projects/{project_id}")

    def list(self, *, page: int = 1, limit: int = 20) -> dict[str, Any]:
        return self._client._request("GET", "/api/v1/projects", params={"page": page, "limit": limit})

    def score(self, project_id: str) -> dict[str, Any]:
        return self._client._request("GET", f"/api/v1/projects/{project_id}/score")

    def delete(self, project_id: str) -> None:
        self._client._request("DELETE", f"/api/v1/projects/{project_id}")


class CodeHardener:
    """Code Hardener API client."""

    def __init__(
        self,
        api_key: str,
        *,
        base_url: str = "https://api.codehardener.com",
        timeout: float = 30.0,
    ):
        self._base_url = base_url.rstrip("/")
        self._client = httpx.Client(
            base_url=self._base_url,
            headers={
                "Authorization": f"Bearer {api_key}",
                "Content-Type": "application/json",
                "User-Agent": "codehardener-python/0.1.0",
            },
            timeout=timeout,
        )
        self.scans = ScansApi(self)
        self.findings = FindingsApi(self)
        self.projects = ProjectsApi(self)

    def _request(
        self,
        method: str,
        path: str,
        *,
        params: Optional[dict[str, Any]] = None,
        json: Optional[dict[str, Any]] = None,
    ) -> dict[str, Any]:
        response = self._client.request(method, path, params=params, json=json)
        if response.status_code >= 400:
            data = response.json()
            raise ApiError(response.status_code, data.get("error", f"HTTP {response.status_code}"))
        if response.status_code == 204:
            return {}
        data = response.json()
        return data.get("data", data)

    def close(self) -> None:
        self._client.close()

    def __enter__(self) -> CodeHardener:
        return self

    def __exit__(self, *args: Any) -> None:
        self.close()
