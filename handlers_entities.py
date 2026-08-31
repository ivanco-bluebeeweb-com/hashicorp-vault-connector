"""KV v2 secrets, Policies, Auth methods, Secrets engines, System status
for HashiCorp Vault Connector.

Confirmed against developer.hashicorp.com/vault/api-docs/secret/kv/kv-v2
and developer.hashicorp.com/vault/api-docs, 2026-08-29:
LIST /v1/{mount}/metadata/{path}, GET/POST /v1/{mount}/data/{path},
DELETE /v1/{mount}/data/{path}, POST /v1/{mount}/undelete/{path},
POST /v1/{mount}/destroy/{path}, LIST/GET/PUT/DELETE /v1/sys/policies/acl/*,
GET /v1/sys/auth, GET /v1/sys/mounts, LIST /v1/{approle_mount}/role,
GET /v1/sys/seal-status, GET /v1/sys/health.
"""
from __future__ import annotations

from imperal_sdk import ActionResult

import hashicorp_vault_client as vc
from app import chat
from handlers_connection import resolve_or_error
from schemas import (
    ListSecretsParams, SecretList,
    GetSecretParams, SecretData,
    CreateSecretParams, UpdateSecretParams, SecretWriteResult,
    DeleteSecretParams, DestroySecretParams, DeleteResult,
    ListPoliciesParams, PolicyList,
    GetPolicyParams, PolicyDetail,
    CreatePolicyParams,
    DeletePolicyParams,
    ListAuthMethodsParams, AuthMethodList, AuthMethod,
    ListSecretsEnginesParams, SecretsEngineList, SecretsEngine,
    ListAppRolesParams, AppRoleList,
    GetSealStatusParams, SealStatus,
    GetHealthParams, HealthStatus,
)


def _secret_data_entity(path: str, resp: dict) -> SecretData:
    data = resp.get("data", {}) or {}
    inner_data = data.get("data", {}) or {}
    meta = data.get("metadata", {}) or {}
    return SecretData(
        path=path, version=meta.get("version", 0), data=inner_data,
        created_time=meta.get("created_time", ""), deleted=bool(meta.get("deletion_time")),
        destroyed=meta.get("destroyed", False),
    )


@chat.function(
    "list_secrets",
    "List secret keys at a path in a KV v2 mount.",
    action_type="read", chain_callable=True, data_model=SecretList,
)
async def list_secrets(ctx, params: ListSecretsParams) -> ActionResult:
    """LIST the KV v2 metadata endpoint to enumerate keys/folders."""
    conn, err = await resolve_or_error(ctx, params.connection_id)
    if err:
        return err
    mount = params.mount.strip("/")
    path = params.path.strip("/")
    try:
        data = await vc.request(ctx, conn, "LIST", f"/{mount}/metadata/{path}", action="list secrets")
    except vc.ClientFail as exc:
        return ActionResult.error(exc.payload["message"], code=exc.payload["code"])
    return ActionResult.success(SecretList(keys=(data.get("data") or {}).get("keys", [])), summary="Secrets listed.")


@chat.function(
    "get_secret",
    "Read one secret's current (or a specific) version from a KV v2 mount.",
    action_type="read", chain_callable=True, data_model=SecretData,
)
async def get_secret(ctx, params: GetSecretParams) -> ActionResult:
    """GET /{mount}/data/{path}, optionally with ?version=N."""
    conn, err = await resolve_or_error(ctx, params.connection_id)
    if err:
        return err
    mount = params.mount.strip("/")
    path = params.path.strip("/")
    url_path = f"/{mount}/data/{path}"
    if params.version:
        url_path += f"?version={params.version}"
    try:
        data = await vc.request(ctx, conn, "GET", url_path, action="get secret")
    except vc.ClientFail as exc:
        return ActionResult.error(exc.payload["message"], code=exc.payload["code"])
    return ActionResult.success(_secret_data_entity(params.path, data), summary="Secret retrieved.")


@chat.function(
    "create_secret",
    "Create a new secret (or a new version if it already exists) at a path in a KV v2 mount.",
    action_type="write", chain_callable=True, event="hashicorp-vault-connector.create_secret",
    effects=["create:secret"], data_model=SecretWriteResult,
)
async def create_secret(ctx, params: CreateSecretParams) -> ActionResult:
    """POST /{mount}/data/{path} {data: {...}}."""
    conn, err = await resolve_or_error(ctx, params.connection_id)
    if err:
        return err
    payload = vc.parse_data_json(params.data_json)
    if payload is None:
        return ActionResult.error("data_json must be a valid JSON object.", code=vc.VAULT_VALIDATION_FAILED)
    mount = params.mount.strip("/")
    path = params.path.strip("/")
    try:
        data = await vc.request(ctx, conn, "POST", f"/{mount}/data/{path}",
                                 json_body={"data": payload}, action="create secret")
    except vc.ClientFail as exc:
        return ActionResult.error(exc.payload["message"], code=exc.payload["code"])
    meta = data.get("data", {}) or {}
    return ActionResult.success(SecretWriteResult(path=params.path, version=meta.get("version", 0)), summary="Secret created.")


@chat.function(
    "update_secret",
    "Write a new version of an existing secret at a path in a KV v2 mount, optionally with a check-and-set "
    "version guard.",
    action_type="write", chain_callable=True, event="hashicorp-vault-connector.update_secret",
    effects=["update:secret"], data_model=SecretWriteResult,
)
async def update_secret(ctx, params: UpdateSecretParams) -> ActionResult:
    """POST /{mount}/data/{path} {data: {...}, options: {cas: N}}."""
    conn, err = await resolve_or_error(ctx, params.connection_id)
    if err:
        return err
    payload = vc.parse_data_json(params.data_json)
    if payload is None:
        return ActionResult.error("data_json must be a valid JSON object.", code=vc.VAULT_VALIDATION_FAILED)
    body: dict = {"data": payload}
    if params.cas:
        body["options"] = {"cas": params.cas}
    mount = params.mount.strip("/")
    path = params.path.strip("/")
    try:
        data = await vc.request(ctx, conn, "POST", f"/{mount}/data/{path}",
                                 json_body=body, action="update secret")
    except vc.ClientFail as exc:
        return ActionResult.error(exc.payload["message"], code=exc.payload["code"])
    meta = data.get("data", {}) or {}
    return ActionResult.success(SecretWriteResult(path=params.path, version=meta.get("version", 0)), summary="Secret updated.")


@chat.function(
    "delete_secret",
    "Soft-delete one or more versions of a secret (recoverable via undelete). Deletes only the latest "
    "version if none specified.",
    action_type="write", chain_callable=True, event="hashicorp-vault-connector.delete_secret",
    effects=["delete:secret"], data_model=DeleteResult,
)
async def delete_secret(ctx, params: DeleteSecretParams) -> ActionResult:
    """DELETE /{mount}/data/{path}, or POST /{mount}/delete/{path} for specific versions."""
    conn, err = await resolve_or_error(ctx, params.connection_id)
    if err:
        return err
    mount = params.mount.strip("/")
    path = params.path.strip("/")
    try:
        if params.versions:
            await vc.request(ctx, conn, "POST", f"/{mount}/delete/{path}",
                              json_body={"versions": params.versions}, action="delete secret versions")
        else:
            await vc.request(ctx, conn, "DELETE", f"/{mount}/data/{path}", action="delete secret")
    except vc.ClientFail as exc:
        return ActionResult.error(exc.payload["message"], code=exc.payload["code"])
    return ActionResult.success(DeleteResult(deleted=True, id=params.path), summary="Secret deleted.")


@chat.function(
    "destroy_secret",
    "Permanently destroy specific versions of a secret -- unlike delete_secret, this cannot be undone via "
    "undelete.",
    action_type="write", chain_callable=True, event="hashicorp-vault-connector.destroy_secret",
    effects=["delete:secret"], data_model=DeleteResult,
)
async def destroy_secret(ctx, params: DestroySecretParams) -> ActionResult:
    """POST /{mount}/destroy/{path} {versions: [...]}."""
    conn, err = await resolve_or_error(ctx, params.connection_id)
    if err:
        return err
    mount = params.mount.strip("/")
    path = params.path.strip("/")
    try:
        await vc.request(ctx, conn, "POST", f"/{mount}/destroy/{path}",
                          json_body={"versions": params.versions}, action="destroy secret versions")
    except vc.ClientFail as exc:
        return ActionResult.error(exc.payload["message"], code=exc.payload["code"])
    return ActionResult.success(DeleteResult(deleted=True, id=params.path), summary="Destroy secret done.")


@chat.function(
    "list_policies",
    "List ACL policies configured on the connected Vault instance.",
    action_type="read", chain_callable=True, data_model=PolicyList,
)
async def list_policies(ctx, params: ListPoliciesParams) -> ActionResult:
    """LIST /sys/policies/acl."""
    conn, err = await resolve_or_error(ctx, params.connection_id)
    if err:
        return err
    try:
        data = await vc.request(ctx, conn, "LIST", "/sys/policies/acl", action="list policies")
    except vc.ClientFail as exc:
        return ActionResult.error(exc.payload["message"], code=exc.payload["code"])
    return ActionResult.success(PolicyList(names=(data.get("data") or {}).get("keys", [])), summary="Policies listed.")


@chat.function(
    "get_policy",
    "Read one ACL policy's HCL rules in full by name.",
    action_type="read", chain_callable=True, data_model=PolicyDetail,
)
async def get_policy(ctx, params: GetPolicyParams) -> ActionResult:
    """GET /sys/policies/acl/{name}."""
    conn, err = await resolve_or_error(ctx, params.connection_id)
    if err:
        return err
    try:
        data = await vc.request(ctx, conn, "GET", f"/sys/policies/acl/{params.name}", action="get policy")
    except vc.ClientFail as exc:
        return ActionResult.error(exc.payload["message"], code=exc.payload["code"])
    body = data.get("data") or {}
    return ActionResult.success(PolicyDetail(name=params.name, policy=body.get("policy", "")), summary="Policy retrieved.")


@chat.function(
    "create_policy",
    "Create or overwrite an ACL policy with the given HCL rules.",
    action_type="write", chain_callable=True, event="hashicorp-vault-connector.create_policy",
    effects=["create:policy"], data_model=DeleteResult,
)
async def create_policy(ctx, params: CreatePolicyParams) -> ActionResult:
    """PUT /sys/policies/acl/{name} {policy: '...'}."""
    conn, err = await resolve_or_error(ctx, params.connection_id)
    if err:
        return err
    try:
        await vc.request(ctx, conn, "PUT", f"/sys/policies/acl/{params.name}",
                          json_body={"policy": params.policy}, action="create policy")
    except vc.ClientFail as exc:
        return ActionResult.error(exc.payload["message"], code=exc.payload["code"])
    return ActionResult.success(DeleteResult(deleted=False, id=params.name), summary="Policy created.")


@chat.function(
    "delete_policy",
    "Permanently delete an ACL policy by name. Cannot be undone.",
    action_type="write", chain_callable=True, event="hashicorp-vault-connector.delete_policy",
    effects=["delete:policy"], data_model=DeleteResult,
)
async def delete_policy(ctx, params: DeletePolicyParams) -> ActionResult:
    """DELETE /sys/policies/acl/{name}."""
    conn, err = await resolve_or_error(ctx, params.connection_id)
    if err:
        return err
    try:
        await vc.request(ctx, conn, "DELETE", f"/sys/policies/acl/{params.name}", action="delete policy")
    except vc.ClientFail as exc:
        return ActionResult.error(exc.payload["message"], code=exc.payload["code"])
    return ActionResult.success(DeleteResult(deleted=True, id=params.name), summary="Policy deleted.")


@chat.function(
    "list_auth_methods",
    "List authentication methods (mounts, e.g. AppRole, LDAP, OIDC) enabled on the connected Vault "
    "instance.",
    action_type="read", chain_callable=True, data_model=AuthMethodList,
)
async def list_auth_methods(ctx, params: ListAuthMethodsParams) -> ActionResult:
    """Read /sys/auth."""
    conn, err = await resolve_or_error(ctx, params.connection_id)
    if err:
        return err
    try:
        data = await vc.request(ctx, conn, "GET", "/sys/auth", action="list auth methods")
    except vc.ClientFail as exc:
        return ActionResult.error(exc.payload["message"], code=exc.payload["code"])
    return ActionResult.success(AuthMethodList(methods=[
        AuthMethod(path=path, type=info.get("type", ""), description=info.get("description", ""))
        for path, info in (data.get("data") or data or {}).items() if isinstance(info, dict)
    ]), summary="Auth methods listed.")


@chat.function(
    "list_secrets_engines",
    "List Secrets Engines (mounts, e.g. KV v2, database, PKI) enabled on the connected Vault instance.",
    action_type="read", chain_callable=True, data_model=SecretsEngineList,
)
async def list_secrets_engines(ctx, params: ListSecretsEnginesParams) -> ActionResult:
    """Read /sys/mounts."""
    conn, err = await resolve_or_error(ctx, params.connection_id)
    if err:
        return err
    try:
        data = await vc.request(ctx, conn, "GET", "/sys/mounts", action="list secrets engines")
    except vc.ClientFail as exc:
        return ActionResult.error(exc.payload["message"], code=exc.payload["code"])
    return ActionResult.success(SecretsEngineList(engines=[
        SecretsEngine(path=path, type=info.get("type", ""), description=info.get("description", ""))
        for path, info in (data.get("data") or data or {}).items() if isinstance(info, dict)
    ]), summary="Secrets engines listed.")


@chat.function(
    "list_approles",
    "List AppRole role names configured under an AppRole auth mount.",
    action_type="read", chain_callable=True, data_model=AppRoleList,
)
async def list_approles(ctx, params: ListAppRolesParams) -> ActionResult:
    """LIST /auth/{mount}/role."""
    conn, err = await resolve_or_error(ctx, params.connection_id)
    if err:
        return err
    mount = params.mount.strip("/")
    try:
        data = await vc.request(ctx, conn, "LIST", f"/auth/{mount}/role", action="list AppRoles")
    except vc.ClientFail as exc:
        return ActionResult.error(exc.payload["message"], code=exc.payload["code"])
    return ActionResult.success(AppRoleList(roles=(data.get("data") or {}).get("keys", [])), summary="Approles listed.")


@chat.function(
    "get_seal_status",
    "Read the connected Vault instance's seal status: sealed/initialized state, version, cluster name.",
    action_type="read", chain_callable=True, data_model=SealStatus,
)
async def get_seal_status(ctx, params: GetSealStatusParams) -> ActionResult:
    """Read /sys/seal-status (unauthenticated-safe endpoint but still routed through the client)."""
    conn, err = await resolve_or_error(ctx, params.connection_id)
    if err:
        return err
    try:
        data = await vc.request(ctx, conn, "GET", "/sys/seal-status", action="get seal status")
    except vc.ClientFail as exc:
        return ActionResult.error(exc.payload["message"], code=exc.payload["code"])
    return ActionResult.success(SealStatus(
        sealed=data.get("sealed", False), initialized=data.get("initialized", False),
        version=data.get("version", ""), cluster_name=data.get("cluster_name", ""),
    ), summary="Seal status retrieved.")


@chat.function(
    "get_health",
    "Read the connected Vault instance's health status: initialized/sealed/standby state.",
    action_type="read", chain_callable=True, data_model=HealthStatus,
)
async def get_health(ctx, params: GetHealthParams) -> ActionResult:
    """Read /sys/health."""
    conn, err = await resolve_or_error(ctx, params.connection_id)
    if err:
        return err
    try:
        data = await vc.request(ctx, conn, "GET", "/sys/health", action="get health")
    except vc.ClientFail as exc:
        return ActionResult.error(exc.payload["message"], code=exc.payload["code"])
    return ActionResult.success(HealthStatus(
        initialized=data.get("initialized", False), sealed=data.get("sealed", False),
        standby=data.get("standby", False), performance_standby=data.get("performance_standby", False),
        version=data.get("version", ""),
    ), summary="Health retrieved.")
