"""ARTEMIS integration descriptor — source of truth for its registry entries."""

from core.integrations._base.descriptor import (
    IntegrationDescriptor,
    IntegrationField,
    register_descriptor,
)

ARTEMIS = register_descriptor(
    IntegrationDescriptor(
        id="artemis",
        category="Offensive Security",
        mcp_server_names=("artemis",),
        fields=(
            IntegrationField("target_environment"),
            IntegrationField("bifrost_url"),
            IntegrationField("api_key", secret=True),
            IntegrationField("mode"),
        ),
    )
)
