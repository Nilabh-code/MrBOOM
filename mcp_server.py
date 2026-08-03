"""DrDOOM MCP Server — exposes DrDOOM's API endpoints as MCP tools via stdio.

This server runs alongside the DrDOOM FastAPI app and provides
MCP tools for:
- Creating and running engagements (recon/breach assessments)
- Getting engagement state, events, and reports
- Chatting with the AI about engagements
- Model discovery and checking
- History management
- Skill management
- Free chat

The MCP server connects to the DrDOOM FastAPI app at the configured port.
"""
from __future__ import annotations

import os
from typing import Any

import httpx
from fastmcp import FastMCP

# ─── Configuration ──────────────────────────────────────────────────────

# DrDOOM API base URL — defaults to localhost:8085
DRDOOM_BASE_URL = os.getenv(
    "DRDOOM_BASE_URL",
    "http://localhost:8085",
)

# Default model configuration for chat/tools
DEFAULT_BASE_URL = os.getenv("DRDOOM_DEFAULT_BASE_URL", "")
DEFAULT_MODEL = os.getenv("DRDOOM_DEFAULT_MODEL", "")
DEFAULT_API_KEY = os.getenv("DRDOOM_DEFAULT_API_KEY", "")

mcp = FastMCP("drdoom")

# ─── HTTP Helpers ───────────────────────────────────────────────────────

def _request(method: str, path: str, *, json: dict | None = None, params: dict | None = None) -> dict[str, Any]:
    """Make an HTTP request to the DrDOOM API."""
    url = f"{DRDOOM_BASE_URL.rstrip('/')}/{path.lstrip('/')}"
    with httpx.Client(timeout=120) as client:
        response = client.request(method, url, json=json, params=params)
        response.raise_for_status()
        return response.json()

def _get(path: str, params: dict | None = None) -> dict[str, Any]:
    return _request("GET", path, params=params)

def _post(path: str, json: dict | None = None) -> dict[str, Any]:
    return _request("POST", path, json=json)

def _delete(path: str) -> dict[str, Any]:
    return _request("DELETE", path)

# ─── Engagement Tools ───────────────────────────────────────────────────

@mcp.tool
def create_engagement(
    name: str,
    scope: list[str],
    exclusions: list[str] = [],
) -> dict[str, Any]:
    """Create a new engagement (recon/breach assessment).

    Args:
        name: Name of the engagement (e.g., 'Target-Alpha').
        scope: List of targets (domains, IPs, etc.) to scan.
        exclusions: List of exclusions (hosts, paths, etc. to skip).

    Returns:
        Engagement ID and session code.
    """
    return _post("/api/engagements", json={
        "name": name,
        "scope": scope,
        "exclusions": exclusions,
    })

@mcp.tool
def run_engagement(
    eid: str,
    problem: str,
    base_url: str = "",
    model: str = "",
    api_key: str = "",
) -> dict[str, Any]:
    """Run a recon/breach assessment on an engagement.

    Args:
        eid: Engagement ID (from create_engagement).
        problem: Problem description (e.g., 'Find exposed services and vulns').
        base_url: Model base URL (optional, uses default if empty).
        model: Model name (optional, uses default if empty).
        api_key: API key for the model (optional).

    Returns:
        OK status — the scan runs in the background.
    """
    return _post(f"/api/engagements/{eid}/run", json={
        "problem": problem,
        "base_url": base_url or DEFAULT_BASE_URL,
        "model": model or DEFAULT_MODEL,
        "api_key": api_key or DEFAULT_API_KEY,
    })

@mcp.tool
def get_engagement_state(eid: str) -> dict[str, Any]:
    """Get the current state of an engagement.

    Args:
        eid: Engagement ID.

    Returns:
        Status, progress, logs, events, and scan findings.
    """
    return _get(f"/api/engagements/{eid}/state")

@mcp.tool
def get_engagement_events(eid: str) -> dict[str, Any]:
    """Get all events for an engagement.

    Args:
        eid: Engagement ID.

    Returns:
        List of events (tools, messages, verifications, etc.).
    """
    return _get(f"/api/engagements/{eid}/events")

@mcp.tool
def get_engagement_report(eid: str) -> dict[str, Any]:
    """Get the full report for a completed engagement.

    Args:
        eid: Engagement ID.

    Returns:
        Full report text (Markdown).
    """
    return _get(f"/api/engagements/{eid}/report")

@mcp.tool
def download_engagement_report(eid: str) -> dict[str, Any]:
    """Download the engagement report file.

    Args:
        eid: Engagement ID.

    Returns:
        Plain text Markdown report with filename header.
    """
    return _get(f"/api/engagements/{eid}/download")

@mcp.tool
def chat_engagement(
    eid: str,
    message: str,
) -> dict[str, Any]:
    """Chat with the AI about an engagement's findings.

    Args:
        eid: Engagement ID.
        message: Question about the engagement.

    Returns:
        AI reply about the engagement.
    """
    return _post(f"/api/engagements/{eid}/chat", json={"message": message})

@mcp.tool
def get_engagement_chat(eid: str) -> dict[str, Any]:
    """Get chat history for an engagement.

    Args:
        eid: Engagement ID.

    Returns:
        List of chat messages.
    """
    return _get(f"/api/engagements/{eid}/chat")

# ─── Model Tools ────────────────────────────────────────────────────────

@mcp.tool
def discover_models(
    base_url: str = "",
    api_key: str = "not-needed",
) -> dict[str, Any]:
    """Discover available models at a given endpoint.

    Args:
        base_url: Model server base URL (e.g., http://localhost:8080).
        api_key: API key for the model server.

    Returns:
        List of available model names.
    """
    return _post("/api/models/discover", json={
        "base_url": base_url,
        "api_key": api_key,
    })

@mcp.tool
def check_model(
    base_url: str,
    model: str,
    api_key: str = "",
) -> dict[str, Any]:
    """Check if a specific model is available/loaded.

    Args:
        base_url: Model server base URL.
        model: Model name to check.
        api_key: API key for the model server.

    Returns:
        Whether the model is available.
    """
    return _post("/api/models/check", json={
        "base_url": base_url,
        "model": model,
        "api_key": api_key,
    })

# ─── Chat Tools ─────────────────────────────────────────────────────────

@mcp.tool
def free_chat(
    message: str,
    model: str = "",
    base_url: str = "",
    api_key: str = "",
    history: list[dict] = [],
) -> dict[str, Any]:
    """Standalone chat with a model — no engagement required.

    Args:
        message: User message.
        model: Model name (optional).
        base_url: Model server base URL (optional).
        api_key: API key (optional).
        history: Message history for context.

    Returns:
        AI reply.
    """
    return _post("/api/chat/free", json={
        "message": message,
        "model": model or DEFAULT_MODEL,
        "base_url": base_url or DEFAULT_BASE_URL,
        "api_key": api_key or DEFAULT_API_KEY,
        "history": history,
    })

# ─── History Tools ──────────────────────────────────────────────────────

@mcp.tool
def list_history() -> dict[str, Any]:
    """List all past scan engagements from disk.

    Returns:
        List of past scans (summary only, no report/events).
    """
    return _get("/api/history")

@mcp.tool
def get_history_scan(eid: str) -> dict[str, Any]:
    """Get full details of a past scan including report.

    Args:
        eid: Engagement ID.

    Returns:
        Full scan details with report.
    """
    return _get(f"/api/history/{eid}")

@mcp.tool
def delete_history_scan(eid: str) -> dict[str, Any]:
    """Delete a past scan from disk.

    Args:
        eid: Engagement ID.

    Returns:
        OK status.
    """
    return _delete(f"/api/history/{eid}")

# ─── Skill Tools ────────────────────────────────────────────────────────

@mcp.tool
def list_skills() -> dict[str, Any]:
    """List all saved skills.

    Returns:
        Skill statistics/summary.
    """
    return _get("/api/skills")

@mcp.tool
def get_skill(name: str) -> dict[str, Any]:
    """Get a skill's source code and metadata.

    Args:
        name: Skill name.

    Returns:
        Skill metadata and source code.
    """
    return _get(f"/api/skills/{name}")

@mcp.tool
def delete_skill(name: str) -> dict[str, Any]:
    """Delete a skill.

    Args:
        name: Skill name.

    Returns:
        OK status.
    """
    return _delete(f"/api/skills/{name}")

@mcp.tool
def generate_skill(
    host: str,
    port: int,
    service: str = "",
    base_url: str = "",
    model: str = "",
    api_key: str = "",
    context: str = "",
) -> dict[str, Any]:
    """Generate a skill for a given host:port/service.

    Args:
        host: Target host.
        port: Target port.
        service: Service name (optional).
        base_url: Model server base URL.
        model: Model name.
        api_key: API key.
        context: Additional context.

    Returns:
        Generated skill result.
    """
    return _post("/api/skills/generate", json={
        "host": host,
        "port": port,
        "service": service,
        "base_url": base_url,
        "model": model,
        "api_key": api_key,
        "context": context,
    })

@mcp.tool
def test_skill(
    name: str,
    host: str = "127.0.0.1",
    port: int = 80,
    timeout: int = 15,
) -> dict[str, Any]:
    """Test a skill against a target.

    Args:
        name: Skill name to test.
        host: Target host.
        port: Target port.
        timeout: Timeout in seconds.

    Returns:
        Test result.
    """
    return _post(f"/api/skills/test/{name}", json={
        "host": host,
        "port": port,
        "timeout": timeout,
    })

# ─── Demo Tool ──────────────────────────────────────────────────────────

@mcp.tool
def start_demo() -> dict[str, Any]:
    """Start a demo run that generates mock events.

    Returns:
        OK status.
    """
    return _post("/api/demo")

# ─── Main ───────────────────────────────────────────────────────────────

if __name__ == "__main__":
    mcp.run()
