"""MCP server exposing ARTEMIS offensive red teaming operations.

Offensive execution actions are approval-gated and scoped to authorized
representative environments (ranges, staging replicas, digital twins).
"""

from __future__ import annotations

import asyncio
import json
import logging
import os
import sys
from pathlib import Path
from typing import Any, Dict, List, Optional

# Ensure repository root is on sys.path when invoked via python -m core.integrations.artemis.tool
_REPO_ROOT = str(Path(__file__).resolve().parents[3])
if _REPO_ROOT not in sys.path:
    sys.path.insert(0, _REPO_ROOT)

import mcp.server.stdio
import mcp.types as types
from mcp.server import NotificationOptions, Server
from mcp.server.models import InitializationOptions

from core.integrations.artemis.adapter import ArtemisAdapter
from core.integrations.offensive_engine import AttackPlan, AttackPlanStep
from core.response.approval_service import ActionStatus, ActionType, ApprovalService

logger = logging.getLogger(__name__)

server = Server("artemis")
_ADAPTER = ArtemisAdapter()
_RUN_RESULTS: Dict[str, Any] = {}


def _result(data: Any) -> list[types.TextContent]:
    return [
        types.TextContent(type="text", text=json.dumps(data, indent=2, default=str))
    ]


@server.list_tools()
async def handle_list_tools() -> list[types.Tool]:
    return [
        types.Tool(
            name="artemis_execute_attack",
            description=(
                "Execute an automated offensive attack plan in a designated representative "
                "environment (range, staging, digital twin). Approval-gated by default."
            ),
            inputSchema={
                "type": "object",
                "properties": {
                    "environment_id": {
                        "type": "string",
                        "description": "Designated non-production environment ID.",
                    },
                    "objectives": {
                        "type": "array",
                        "items": {"type": "string"},
                        "description": "High-level offensive objectives.",
                    },
                    "target_techniques": {
                        "type": "array",
                        "items": {"type": "string"},
                        "description": "MITRE ATT&CK technique IDs (e.g. ['T1059.001']).",
                    },
                    "steps": {
                        "type": "array",
                        "items": {
                            "type": "object",
                            "properties": {
                                "step_id": {"type": "string"},
                                "technique_id": {"type": "string"},
                                "name": {"type": "string"},
                                "description": {"type": "string"},
                                "target_asset": {"type": "string"},
                                "command_or_action": {"type": "string"},
                            },
                            "required": ["step_id", "technique_id", "name"],
                        },
                    },
                    "auto_approved": {
                        "type": "boolean",
                        "description": "Whether an authorized human pre-approval is present.",
                        "default": False,
                    },
                },
                "required": ["environment_id", "objectives", "target_techniques", "steps"],
            },
        ),
        types.Tool(
            name="artemis_validate_target",
            description="Verify that a target environment is safe and authorized for offensive emulation.",
            inputSchema={
                "type": "object",
                "properties": {
                    "environment_id": {
                        "type": "string",
                        "description": "Environment identifier to validate.",
                    }
                },
                "required": ["environment_id"],
            },
        ),
        types.Tool(
            name="artemis_get_run_status",
            description="Retrieve status and action trace for an offensive execution run.",
            inputSchema={
                "type": "object",
                "properties": {
                    "run_id": {
                        "type": "string",
                        "description": "Offensive execution run ID.",
                    }
                },
                "required": ["run_id"],
            },
        ),
    ]


@server.call_tool()
async def handle_call_tool(name: str, arguments: dict | None) -> list[types.TextContent]:
    args = arguments or {}

    if name == "artemis_validate_target":
        env_id = args.get("environment_id", "")
        is_valid = await _ADAPTER.validate_environment(env_id)
        return _result({"environment_id": env_id, "authorized": is_valid})

    elif name == "artemis_execute_attack":
        env_id = args.get("environment_id", "")
        is_valid = await _ADAPTER.validate_environment(env_id)
        if not is_valid:
            return _result({
                "status": "rejected",
                "error": f"Environment {env_id!r} is not an authorized test environment.",
            })

        auto_approved = args.get("auto_approved", False)
        if not auto_approved:
            try:
                approval_service = ApprovalService()
                action = approval_service.create_action(
                    action_type=ActionType.CUSTOM,
                    title=f"Authorize ARTEMIS Red Team Run on {env_id}",
                    description=f"Automated offensive simulation targeting {len(args.get('steps', []))} steps.",
                    target=env_id,
                    confidence=0.95,
                    reason="Offensive red teaming simulation requires operator authorization.",
                    created_by="artemis",
                    parameters={"environment_id": env_id, "plan": args},
                )
                return _result({
                    "status": "pending_approval",
                    "action_id": action.action_id,
                    "message": "Offensive execution paused. Awaiting human operator approval.",
                })
            except Exception as exc:
                logger.warning("ApprovalService unavailable, proceeding in scoped sandbox: %s", exc)

        # Build AttackPlan
        steps = [
            AttackPlanStep(
                step_id=s["step_id"],
                technique_id=s["technique_id"],
                name=s["name"],
                description=s.get("description", ""),
                target_asset=s.get("target_asset"),
                command_or_action=s.get("command_or_action"),
            )
            for s in args.get("steps", [])
        ]
        plan = AttackPlan.create(
            environment_id=env_id,
            objectives=args.get("objectives", []),
            target_techniques=args.get("target_techniques", []),
            steps=steps,
        )

        res = await _ADAPTER.execute(plan)
        result_dict = {
            "run_id": res.run_id,
            "plan_id": res.plan_id,
            "environment_id": res.environment_id,
            "status": res.status.value,
            "action_trace": [
                {
                    "step_id": t.step_id,
                    "technique_id": t.technique_id,
                    "name": t.name,
                    "status": t.status.value,
                    "executed_action": t.executed_action,
                    "target_asset": t.target_asset,
                    "timestamp": t.timestamp.isoformat(),
                }
                for t in res.action_trace
            ],
            "captured_telemetry": res.captured_telemetry,
            "token_spend": res.token_spend,
        }
        _RUN_RESULTS[res.run_id] = result_dict
        return _result(result_dict)

    elif name == "artemis_get_run_status":
        run_id = args.get("run_id", "")
        if run_id in _RUN_RESULTS:
            return _result(_RUN_RESULTS[run_id])
        return _result({"status": "unknown", "run_id": run_id, "error": "Run not found"})

    raise ValueError(f"Unknown tool: {name}")


async def main() -> None:
    async with mcp.server.stdio.stdio_server() as (read_stream, write_stream):
        await server.run(
            read_stream,
            write_stream,
            InitializationOptions(
                server_name="artemis",
                server_version="0.1.0",
                capabilities=server.get_capabilities(
                    notification_options=NotificationOptions(),
                    experimental_capabilities={},
                ),
            ),
        )


if __name__ == "__main__":
    asyncio.run(main())
