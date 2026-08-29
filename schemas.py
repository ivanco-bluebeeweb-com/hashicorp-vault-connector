"""Pydantic param/result models for HashiCorp Vault Connector.

Same "explicit ConnectionScoped mixin + one params + one result class per
@chat.function" shape as every other connector this session's schemas.py.
"""
from __future__ import annotations

from pydantic import BaseModel, Field


class ConnectionScoped(BaseModel):
    connection_id: str = Field("", description="Which saved Vault instance to use. Omit if only one is connected.")


# ── Connection lifecycle ────────────────────────────────────────────────

class ConnectVaultParams(BaseModel):
    label: str = Field("", description="A friendly name for this Vault instance, e.g. 'Prod cluster'.")
    base_url: str = Field(description="Your Vault instance's base URL, e.g. https://vault.yourcompany.com:8200")
    role_id: str = Field(description="AppRole RoleID (vault read auth/approle/role/<name>/role-id).")
    secret_id: str = Field(description="AppRole SecretID (vault write -f auth/approle/role/<name>/secret-id).")
    verify_ssl: bool = Field(True, description="Verify the Vault instance's TLS certificate. Turn off only for self-signed certs in trusted internal networks.")


class ConnectVaultResult(BaseModel):
    connection_id: str = ""
    label: str = ""


class DisconnectVaultParams(BaseModel):
    connection_id: str = Field(description="The connection id to disconnect, from list_connections.")


class DeleteResult(BaseModel):
    deleted: bool = False
    id: str = ""


class VaultConnection(BaseModel):
    id: str = ""
    label: str = ""
    base_url: str = ""


class ConnectionList(BaseModel):
    connections: list[VaultConnection] = Field(default_factory=list)


class ListConnectionsParams(BaseModel):
    pass


# ── KV v2 secrets ────────────────────────────────────────────────────────

class ListSecretsParams(ConnectionScoped):
    mount: str = Field("secret", description="The KV v2 secrets engine mount path, e.g. 'secret'.")
    path: str = Field("", description="Folder path to list within the mount, e.g. 'apps/'. Empty lists the root.")


class SecretList(BaseModel):
    keys: list[str] = Field(default_factory=list)


class GetSecretParams(ConnectionScoped):
    mount: str = Field("secret", description="The KV v2 secrets engine mount path.")
    path: str = Field(description="The secret's path within the mount, e.g. 'apps/api-key'.")
    version: int = Field(0, description="Specific version to read. 0 reads the latest version.")


class SecretData(BaseModel):
    path: str = ""
    version: int = 0
    data: dict = Field(default_factory=dict)
    created_time: str = ""
    deleted: bool = False
    destroyed: bool = False


class CreateSecretParams(ConnectionScoped):
    mount: str = Field("secret", description="The KV v2 secrets engine mount path.")
    path: str = Field(description="The secret's path within the mount, e.g. 'apps/api-key'.")
    data_json: str = Field(description="JSON object of key/value pairs to store, e.g. '{\"api_key\": \"abc123\"}'.")


class SecretWriteResult(BaseModel):
    path: str = ""
    version: int = 0


class UpdateSecretParams(CreateSecretParams):
    cas: int = Field(0, description="Check-and-set version for optimistic concurrency. 0 skips the check.")


class DeleteSecretParams(ConnectionScoped):
    mount: str = Field("secret", description="The KV v2 secrets engine mount path.")
    path: str = Field(description="The secret's path within the mount.")
    versions: list[int] = Field(default_factory=list, description="Specific versions to soft-delete. Empty deletes the latest version.")


class DestroySecretParams(ConnectionScoped):
    mount: str = Field("secret", description="The KV v2 secrets engine mount path.")
    path: str = Field(description="The secret's path within the mount.")
    versions: list[int] = Field(description="Specific versions to PERMANENTLY destroy. Cannot be undone.")


class UndeleteSecretParams(ConnectionScoped):
    mount: str = Field("secret", description="The KV v2 secrets engine mount path.")
    path: str = Field(description="The secret's path within the mount.")
    versions: list[int] = Field(description="Specific soft-deleted versions to restore.")


class GetSecretMetadataParams(ConnectionScoped):
    mount: str = Field("secret", description="The KV v2 secrets engine mount path.")
    path: str = Field(description="The secret's path within the mount.")


class SecretVersionInfo(BaseModel):
    version: int = 0
    created_time: str = ""
    deletion_time: str = ""
    destroyed: bool = False


class SecretMetadata(BaseModel):
    path: str = ""
    current_version: int = 0
    oldest_version: int = 0
    versions: list[SecretVersionInfo] = Field(default_factory=list)


# ── Policies ─────────────────────────────────────────────────────────────

class ListPoliciesParams(ConnectionScoped):
    pass


class PolicyList(BaseModel):
    policies: list[str] = Field(default_factory=list)


class GetPolicyParams(ConnectionScoped):
    name: str = Field(description="The policy's name, from list_policies.")


class PolicyDetail(BaseModel):
    name: str = ""
    policy_hcl: str = ""


class CreatePolicyParams(ConnectionScoped):
    name: str = Field(description="Name for the new policy.")
    policy_hcl: str = Field(description="The policy rules in HCL (e.g. 'path \"secret/data/*\" { capabilities = [\"read\"] }').")


class DeletePolicyParams(ConnectionScoped):
    name: str = Field(description="The policy's name to permanently delete.")


# ── Auth methods & mounts ────────────────────────────────────────────────

class ListAuthMethodsParams(ConnectionScoped):
    pass


class AuthMethod(BaseModel):
    path: str = ""
    type: str = ""
    description: str = ""


class AuthMethodList(BaseModel):
    methods: list[AuthMethod] = Field(default_factory=list)


class ListSecretsEnginesParams(ConnectionScoped):
    pass


class SecretsEngine(BaseModel):
    path: str = ""
    type: str = ""
    description: str = ""


class SecretsEngineList(BaseModel):
    engines: list[SecretsEngine] = Field(default_factory=list)


class ListAppRolesParams(ConnectionScoped):
    mount: str = Field("approle", description="The AppRole auth method mount path.")


class AppRoleList(BaseModel):
    roles: list[str] = Field(default_factory=list)


# ── System status ─────────────────────────────────────────────────────────

class GetSealStatusParams(ConnectionScoped):
    pass


class SealStatus(BaseModel):
    sealed: bool = False
    initialized: bool = False
    version: str = ""
    cluster_name: str = ""


class GetHealthParams(ConnectionScoped):
    pass


class AuditVaultInstanceParams(ConnectionScoped):
    pass


class VaultInstanceReport(BaseModel):
    sealed: bool = False
    version: str = ""
    cluster_name: str = ""
    total_mounts: int = 0
    kv_mount_count: int = 0
    kv_mounts: list[str] = Field(default_factory=list)
    policy_count: int = 0


class HealthStatus(BaseModel):
    initialized: bool = False
    sealed: bool = False
    standby: bool = False
    performance_standby: bool = False
    version: str = ""


# ── Reports ────────────────────────────────────────────────────────────────

class AuditVaultAccessParams(ConnectionScoped):
    mount: str = Field("secret", description="The KV v2 secrets engine mount path to audit.")


class VaultAccessReport(BaseModel):
    sealed: bool = False
    initialized: bool = False
    version: str = ""
    secret_count: int = 0
    policy_count: int = 0
    auth_method_count: int = 0
    notes: list[str] = Field(default_factory=list)
