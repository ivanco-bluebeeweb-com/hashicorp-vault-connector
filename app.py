"""Extension declaration, secrets, lifecycle hooks.

WHY BYOK, same reasoning as every other connector this session -- the
user's own HashiCorp Vault cluster (KV v2 secrets, policies, auth
methods) is managed via their own Vault instance and credentials.

WHY APPROLE AUTHENTICATION, CONFIRMED against developer.hashicorp.com/
vault/api-docs/auth/approle and developer.hashicorp.com/vault/docs/auth/
approle, 2026-08-29: AppRole is Vault's own recommended authentication
method for machine/service clients (as opposed to human operators using
tokens/OIDC/LDAP) -- it exchanges a RoleID (like a username) plus a
SecretID (like a password) for a short-lived Vault token via
POST /v1/auth/approle/login. This matches the same shape as every other
OAuth2/AppRole-style BYOK connector this session (Databricks Service
Principal, Bitwarden client_credentials): the user creates an AppRole in
their own Vault, generates a RoleID + SecretID, and pastes both here.

WHY KV V2 AS THE PRIMARY SECRETS ENGINE, per developer.hashicorp.com/
vault/api-docs/secret/kv/kv-v2: KV v2 is Vault's versioned key/value
secrets engine and the default recommended mount for storing arbitrary
secrets (as opposed to KV v1, which is unversioned and considered
legacy) -- this connector targets KV v2's data/metadata/versions model.

WHY EACH CONNECTION STORES base_url + role_id + secret_id + a live
client_token (refreshed via login), SAME SHAPE AS EVERY OTHER
TOKEN-EXCHANGE CONNECTOR THIS SESSION -- Vault tokens carry a TTL and can
be renewed; ensure_fresh_token() re-logs-in near expiry.
"""
from __future__ import annotations

from imperal_sdk import ChatExtension, Extension

ext = Extension(
    "hashicorp-vault-connector",
    version="0.1.0",
    display_name="HashiCorp Vault",
    icon="icon.svg",
    capabilities=["vault:read", "vault:write"],
    description=(
        "Connect your own HashiCorp Vault cluster (AppRole authentication) to read and manage KV v2 secrets, "
        "policies, and auth methods -- full read/write plus value-add vault health and secret-rotation reports. "
        "Secret values are never logged."
    ),
)

chat = ChatExtension(ext)
