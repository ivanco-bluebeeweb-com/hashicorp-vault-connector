"""Thin HTTP client for HashiCorp Vault's HTTP API + AppRole auth.

Same "fail()-dict + ClientFail exception + generic request() helper"
shape as every other connector this session's *_client.py. Confirmed
against developer.hashicorp.com/vault/api-docs/auth/approle and
developer.hashicorp.com/vault/api-docs/secret/kv/kv-v2, 2026-08-29:

- Login: POST {base_url}/v1/auth/approle/login {role_id, secret_id} ->
  auth.client_token + auth.lease_duration.
- KV v2 reads/writes: GET/POST {base_url}/v1/{mount}/data/{path},
  LIST {base_url}/v1/{mount}/metadata/{path},
  DELETE {base_url}/v1/{mount}/data/{path} (soft-delete latest version),
  POST {base_url}/v1/{mount}/undelete/{path}, POST .../destroy/{path}.
- All authenticated calls carry header X-Vault-Token.
"""
from __future__ import annotations

import json
import time
from typing import Any

import httpx

VAULT_NOT_CONNECTED = "VAULT_NOT_CONNECTED"
VAULT_UNAUTHORIZED = "VAULT_UNAUTHORIZED"
VAULT_FORBIDDEN = "VAULT_FORBIDDEN"
VAULT_NOT_FOUND = "VAULT_NOT_FOUND"
VAULT_RATE_LIMITED = "VAULT_RATE_LIMITED"
VAULT_BACKEND_ERROR = "VAULT_BACKEND_ERROR"
VAULT_VALIDATION_FAILED = "VAULT_VALIDATION_FAILED"
VAULT_RESPONSE_UNEXPECTED = "VAULT_RESPONSE_UNEXPECTED"
VAULT_SEALED = "VAULT_SEALED"

_MESSAGES = {
    VAULT_NOT_CONNECTED: "No HashiCorp Vault instance connected. Connect one first.",
    VAULT_UNAUTHORIZED: "Vault rejected the RoleID/SecretID as invalid or expired.",
    VAULT_FORBIDDEN: "Vault denied access -- this AppRole's policy does not permit this path.",
    VAULT_NOT_FOUND: "That Vault path was not found.",
    VAULT_RATE_LIMITED: "Vault rate-limited this request. Try again shortly.",
    VAULT_BACKEND_ERROR: "Vault returned an error.",
    VAULT_VALIDATION_FAILED: "Vault rejected the request as invalid.",
    VAULT_RESPONSE_UNEXPECTED: "Vault returned an unexpected response shape.",
    VAULT_SEALED: "Vault is sealed and cannot process requests until unsealed.",
}


class ClientFail(Exception):
    def __init__(self, payload: dict):
        self.payload = payload
        super().__init__(payload.get("message", "Vault request failed"))


def fail(code: str, detail: str = "") -> dict:
    msg = _MESSAGES.get(code, "Vault request failed.")
    if detail:
        msg = f"{msg} ({detail})"
    return {"ok": False, "code": code, "message": msg}


def _check_status(resp: httpx.Response, action: str) -> Any:
    if resp.status_code == 400:
        raise ClientFail(fail(VAULT_VALIDATION_FAILED, f"{action}: {resp.text[:300]}"))
    if resp.status_code == 401:
        raise ClientFail(fail(VAULT_UNAUTHORIZED, action))
    if resp.status_code == 403:
        raise ClientFail(fail(VAULT_FORBIDDEN, action))
    if resp.status_code == 404:
        raise ClientFail(fail(VAULT_NOT_FOUND, action))
    if resp.status_code == 429:
        raise ClientFail(fail(VAULT_RATE_LIMITED, action))
    if resp.status_code == 503:
        raise ClientFail(fail(VAULT_SEALED, action))
    if resp.status_code >= 500:
        raise ClientFail(fail(VAULT_BACKEND_ERROR, f"{action}: HTTP {resp.status_code}"))
    if resp.status_code >= 400:
        raise ClientFail(fail(VAULT_BACKEND_ERROR, f"{action}: HTTP {resp.status_code} {resp.text[:300]}"))
    if not resp.content:
        return {}
    try:
        return resp.json()
    except ValueError:
        raise ClientFail(fail(VAULT_RESPONSE_UNEXPECTED, f"{action}: non-JSON response"))


async def login(base_url: str, role_id: str, secret_id: str, verify_ssl: bool = True) -> dict:
    """Exchange RoleID+SecretID for a client token via AppRole login."""
    url = f"{base_url.rstrip('/')}/v1/auth/approle/login"
    async with httpx.AsyncClient(verify=verify_ssl, timeout=30.0) as client:
        resp = await client.post(url, json={"role_id": role_id, "secret_id": secret_id})
    data = _check_status(resp, "AppRole login")
    auth = data.get("auth") or {}
    if not auth.get("client_token"):
        raise ClientFail(fail(VAULT_RESPONSE_UNEXPECTED, "login response missing auth.client_token"))
    return {
        "client_token": auth["client_token"],
        "lease_duration": auth.get("lease_duration", 3600),
        "obtained_at": time.time(),
    }


async def ensure_fresh_token(ctx, conn: dict) -> dict:
    """Re-login if the stored client_token is missing or near expiry (80% of lease)."""
    obtained_at = conn.get("obtained_at", 0)
    lease = conn.get("lease_duration", 3600)
    if conn.get("client_token") and (time.time() - obtained_at) < (lease * 0.8):
        return conn
    fresh = await login(conn["base_url"], conn["role_id"], conn["secret_id"], conn.get("verify_ssl", True))
    conn = {**conn, **fresh}
    return conn


def _headers(client_token: str) -> dict:
    return {"X-Vault-Token": client_token, "Content-Type": "application/json"}


async def request(ctx, conn: dict, method: str, path: str, *, json_body: Any = None,
                   action: str = "request") -> Any:
    """Generic authenticated call against a connection's own Vault base_url."""
    base_url = (conn.get("base_url") or "").rstrip("/")
    client_token = conn.get("client_token", "")
    if not base_url or not client_token:
        raise ClientFail(fail(VAULT_NOT_CONNECTED))
    url = f"{base_url}/v1{path}"
    headers = _headers(client_token)
    async with httpx.AsyncClient(verify=conn.get("verify_ssl", True), timeout=30.0) as client:
        resp = await client.request(method, url, headers=headers, json=json_body)
    return _check_status(resp, action)


def parse_data_json(data_json: str) -> dict | None:
    try:
        data = json.loads(data_json)
    except (TypeError, ValueError):
        return None
    return data if isinstance(data, dict) else None
