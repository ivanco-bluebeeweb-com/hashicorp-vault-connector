"""Value-add reports for HashiCorp Vault Connector -- instance health
overview (seal status, mount/policy counts), same "aggregate raw records
into one glance" shape as every other connector's handlers_reports.py
this session.
"""
from __future__ import annotations

from imperal_sdk import ActionResult

import hashicorp_vault_client as vc
from app import chat
from handlers_connection import resolve_or_error
from schemas import (
    AuditVaultInstanceParams, VaultInstanceReport,
)


@chat.function(
    "audit_vault_instance",
    "Build one aggregated health report for the connected Vault instance: seal status, secrets engine and "
    "policy counts.",
    action_type="read", chain_callable=True, data_model=VaultInstanceReport,
)
async def audit_vault_instance(ctx, params: AuditVaultInstanceParams) -> ActionResult:
    """Combine /sys/seal-status, /sys/mounts, /sys/policies/acl into one snapshot."""
    conn, err = await resolve_or_error(ctx, params.connection_id)
    if err:
        return err
    try:
        seal = await vc.request(ctx, conn, "GET", "/sys/seal-status", action="seal status for audit")
        mounts = await vc.request(ctx, conn, "GET", "/sys/mounts", action="list mounts for audit")
        policies = await vc.request(ctx, conn, "LIST", "/sys/policies/acl", action="list policies for audit")
    except vc.ClientFail as exc:
        return ActionResult.error(exc.payload["message"], code=exc.payload["code"])
    mount_data = mounts if isinstance(mounts, dict) else {}
    kv_mounts = [
        path for path, info in mount_data.items()
        if isinstance(info, dict) and info.get("type") == "kv"
    ]
    policy_list = (policies.get("data") or {}).get("keys", []) if isinstance(policies, dict) else []
    return ActionResult.success(VaultInstanceReport(
        sealed=seal.get("sealed", False),
        version=seal.get("version", ""),
        cluster_name=seal.get("cluster_name", ""),
        total_mounts=len(mount_data),
        kv_mount_count=len(kv_mounts),
        kv_mounts=kv_mounts,
        policy_count=len(policy_list),
    ), summary="Vault instance audit ready.")
