"""Panel UI -- connections list/connect form + the one required "App
settings" entry point, same shape as Bitwarden Connector's panels.py
(corrected UI kwargs: ui.Input uses param_name not name; ui.Form uses
action not on_submit; ui.Stack/ui.Form do not accept full_width).

SIDEBAR CONTENT -- NO CARDS ANYWHERE, per ~/UI_INTERFACE_STANDARD.md's
"left sidebar, no decorated cards" rule. Disconnect lives only in the
"App settings" screen (panels_settings.py). The one secondary "App
settings" button is always the LAST element at the bottom of the sidebar.

PER ~/UI_INTERFACE_STANDARD.md (2026-08-21 addendum): every Input carries
its own visible label, the placeholder text is always contextually
specific, the form's own container is stretched to the full width of the
left sidebar, and the form's inner content is stretched to fill that
container. The "How do I set this up?" instructions live ONLY in the help
modal below -- never duplicated as static sidebar text.
"""
from __future__ import annotations

from imperal_sdk import ui

from app import ext
import handlers_connection as h


def _settings_button() -> ui.UINode:
    return ui.Button(
        "App settings", variant="secondary", size="sm", full_width=True,
        icon="settings", on_click=ui.Call("__panel__vault_settings"),
    )


def _connection_row(c: dict) -> ui.UINode:
    label = c.get("label") or "HashiCorp Vault instance"
    return ui.Stack(direction="v", gap=1, children=[
        ui.Text(label, variant="body"),
        ui.Text(c.get("base_url", ""), variant="caption"),
    ])


def _connections_section(connections: list[dict]) -> ui.UINode:
    if not connections:
        return ui.Text("No Vault instances connected yet.", variant="caption")
    children: list[ui.UINode] = []
    for i, c in enumerate(connections):
        if i > 0:
            children.append(ui.Divider())
        children.append(_connection_row(c))
    return ui.Stack(direction="v", gap=2, children=children)


def _help_modal() -> ui.UINode:
    return ui.Modal(
        trigger=ui.Button("How do I set this up?", variant="link", size="sm"),
        title="Connecting HashiCorp Vault",
        children=[
            ui.Text(
                "1. In your Vault instance, enable the AppRole auth method: "
                "vault auth enable approle\n"
                "2. Create a role with a policy attached: "
                "vault write auth/approle/role/imperal token_policies=\"your-policy\"\n"
                "3. Read the RoleID: vault read auth/approle/role/imperal/role-id\n"
                "4. Generate a SecretID: vault write -f auth/approle/role/imperal/secret-id\n"
                "5. Paste your Vault URL, RoleID and SecretID below.",
                variant="body",
            ),
        ],
    )


@ext.panel("sidebar", slot="left")
async def sidebar(ctx, **kwargs) -> object:
    connections = await h._load_connections(ctx)
    return ui.Stack(direction="v", gap=3, children=[
        ui.Text("HashiCorp Vault", variant="heading"),
        _connections_section(connections),
        ui.Divider(),
        ui.Form(
            submit_label="Connect",
            action=ui.Call("connect_vault"),
            children=[
                ui.Stack(direction="v", gap=1, children=[
                    ui.Text("Label", variant="label"),
                    ui.Input(param_name="label", placeholder="e.g. Prod cluster"),
                ]),
                ui.Stack(direction="v", gap=1, children=[
                    ui.Text("Vault URL", variant="label"),
                    ui.Input(param_name="base_url", placeholder="https://vault.yourcompany.com:8200"),
                ]),
                ui.Stack(direction="v", gap=1, children=[
                    ui.Text("RoleID", variant="label"),
                    ui.Input(param_name="role_id", placeholder="AppRole RoleID"),
                ]),
                ui.Stack(direction="v", gap=1, children=[
                    ui.Text("SecretID", variant="label"),
                    ui.Input(param_name="secret_id", placeholder="AppRole SecretID"),
                ]),
            ],
        ),
        _help_modal(),
        ui.Divider(),
        _settings_button(),
    ])
