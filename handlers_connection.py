"""Connection lifecycle: connect (AppRole login), list, disconnect.

Same "secrets-store list of dicts" shape as every other BYOK connector
this session's handlers_connection.py.
"""
from __future__ import annotations

import json
import uuid

from imperal_sdk import ActionResult

import hashicorp_vault_client as vc
from app import chat
from schemas import (
    ConnectVaultParams, ConnectVaultResult,
    DisconnectVaultParams, DeleteResult,
    VaultConnection, ConnectionList, ListConnectionsParams,
)

_CONNECTIONS_SECRET = "vault_connections"


async def _load_connections(ctx) -> list[dict]:
    raw = await ctx.secrets.get(_CONNECTIONS_SECRET)
    if not raw:
        return []
    try:
        data = json.loads(raw)
    except (TypeError, ValueError):
        return []
    return data if isinstance(data, list) else []


async def _save_connections(ctx, connections: list[dict]) -> None:
    await ctx.secrets.set(_CONNECTIONS_SECRET, json.dumps(connections))


async def resolve_connection(ctx, connection_id: str = "") -> dict | None:
    connections = await _load_connections(ctx)
    if not connections:
        return None
    if connection_id:
        return next((c for c in connections if c.get("id") == connection_id), None)
    return connections[0]


async def resolve_or_error(ctx, connection_id: str = ""):
    conn = await resolve_connection(ctx, connection_id)
    if not conn:
        return None, ActionResult.error(
            "No HashiCorp Vault instance found. Connect one with connect_vault first.",
            code=vc.VAULT_NOT_CONNECTED,
        )
    conn = await vc.ensure_fresh_token(ctx, conn)
    await _persist_conn(ctx, conn)
    return conn, None


async def _persist_conn(ctx, conn: dict) -> None:
    connections = await _load_connections(ctx)
    for i, c in enumerate(connections):
        if c.get("id") == conn.get("id"):
            connections[i] = conn
            break
    await _save_connections(ctx, connections)


def _connection_to_entity(c: dict) -> VaultConnection:
    return VaultConnection(
        id=c.get("id", ""), label=c.get("label") or "HashiCorp Vault",
        base_url=c.get("base_url", ""),
    )


@chat.function(
    "connect_vault",
    "Connect your own HashiCorp Vault instance by saving its base URL plus an AppRole RoleID/SecretID, "
    "after checking it actually works.",
    action_type="write", chain_callable=True, event="hashicorp-vault-connector.connect_vault",
    effects=["create:connection"], data_model=ConnectVaultResult,
)
async def connect_vault(ctx, params: ConnectVaultParams) -> ActionResult:
    """Log in via AppRole and save the connection if it succeeds."""
    try:
        auth = await vc.login(params.base_url, params.role_id, params.secret_id, params.verify_ssl)
    except vc.ClientFail as exc:
        return ActionResult.error(exc.payload["message"], code=exc.payload["code"])
    connection_id = str(uuid.uuid4())
    conn = {
        "id": connection_id, "label": params.label or "HashiCorp Vault",
        "base_url": params.base_url.rstrip("/"), "role_id": params.role_id,
        "secret_id": params.secret_id, "verify_ssl": params.verify_ssl,
        **auth,
    }
    connections = await _load_connections(ctx)
    connections.append(conn)
    await _save_connections(ctx, connections)
    return ActionResult.success(ConnectVaultResult(connection_id=connection_id, label=conn["label"]), summary="Vault connected.")


@chat.function(
    "disconnect_vault",
    "Disconnect a HashiCorp Vault instance: deletes the saved RoleID/SecretID/token. Nothing in Vault "
    "itself is changed.",
    action_type="write", chain_callable=True, event="hashicorp-vault-connector.disconnect_vault",
    effects=["delete:connection"], data_model=DeleteResult,
)
async def disconnect_vault(ctx, params: DisconnectVaultParams) -> ActionResult:
    """Remove one saved Vault connection by id."""
    connections = await _load_connections(ctx)
    remaining = [c for c in connections if c.get("id") != params.connection_id]
    if len(remaining) == len(connections):
        return ActionResult.error("Connection not found.", code=vc.VAULT_NOT_FOUND)
    await _save_connections(ctx, remaining)
    return ActionResult.success(DeleteResult(deleted=True, id=params.connection_id), summary="Vault disconnected.")


@chat.function(
    "list_connections",
    "List the connected HashiCorp Vault instances.",
    action_type="read", chain_callable=True, data_model=ConnectionList,
)
async def list_connections(ctx, params: ListConnectionsParams) -> ActionResult:
    """List saved Vault connections."""
    connections = await _load_connections(ctx)
    return ActionResult.success(ConnectionList(connections=[_connection_to_entity(c) for c in connections]), summary="Connections listed.")
