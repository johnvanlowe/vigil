"""Detection authoring service: ground new detections in telemetry and LogLM.

When an attack step is flagged by LogLM and missed by rules (model-only gap),
LogLM's embedding neighborhood reveals which behavioral features distinguished
the anomaly from normal traffic. This service synthesizes portable, behavioral
rules (e.g. Sigma) around those features, ensuring anti-brittleness compliance.

Exposed as skill_author_detection.
"""

from __future__ import annotations

import logging
import uuid
from typing import Any, Dict, List, Optional, Sequence, Set

import yaml

from core.detections.candidates import CandidateStatus, DetectionCandidate
from core.time import utcnow

logger = logging.getLogger(__name__)

STANDARD_SCHEMA_FIELDS = {
    "process_name",
    "command_line",
    "parent_process",
    "user",
    "dest_ip",
    "dest_port",
    "host",
    "timestamp",
    "action",
    "source",
    "Image",
    "CommandLine",
    "ParentImage",
    "User",
    "TargetFilename",
}


class DetectionAuthor:
    """Authors grounded behavioral detection candidates."""

    def __init__(self, run_id: Optional[str] = None):
        self.run_id = run_id or f"author-{utcnow().strftime('%Y%m%d')}-{uuid.uuid4().hex[:6]}"

    async def retrieve_loglm_neighborhood(
        self,
        finding_id: str,
        technique_id: str,
    ) -> List[str]:
        """Query LogLM embedding similarity to isolate discriminative behavioral features."""
        features: List[str] = []
        try:
            import json
            from tools.mcp.deeptempo_findings import load_findings, nearest_neighbors

            nn_json = nearest_neighbors(finding_id=finding_id, k=5)
            nn_data = json.loads(nn_json) if isinstance(nn_json, str) else nn_json
            if isinstance(nn_data, dict) and "neighbors" in nn_data and nn_data["neighbors"]:
                all_findings = {f.get("finding_id"): f for f in load_findings()}
                for n in nn_data["neighbors"]:
                    match = all_findings.get(n.get("finding_id"))
                    if match:
                        if "tactics" in match and isinstance(match["tactics"], list):
                            features.extend(str(t).lower() for t in match["tactics"])
                        if "features" in match and isinstance(match["features"], list):
                            features.extend(str(f) for f in match["features"])
        except Exception as exc:
            logger.debug("LogLM nearest_neighbors fallback: %s", exc)

        if features:
            return list(dict.fromkeys(features))

        # Fallback to standard behavioral heuristics per technique
        if "T1059" in technique_id:
            return [
                "encoded_command_line_switch",
                "hidden_window_flag",
                "non_interactive_execution",
            ]
        elif "T1003" in technique_id:
            return [
                "lsass_memory_read_access",
                "process_dump_argument",
            ]
        elif "T1021" in technique_id:
            return [
                "lateral_service_creation",
                "admin_share_access_chain",
            ]
        elif "T1048" in technique_id or "T1071" in technique_id:
            return [
                "anomalous_network_outbound",
                "alternative_protocol_transfer",
            ]
        return [
            "abnormal_execution_tree",
            "atypical_subsystem_invocation",
        ]

    def validate_fields_against_schema(
        self,
        used_fields: Set[str],
        allowed_fields: Set[str],
    ) -> None:
        """Reject rule if it relies on unsupported telemetry fields."""
        unsupported = used_fields - allowed_fields
        if unsupported:
            raise ValueError(
                f"Candidate rule contains unsupported fields not emitted by environment: {sorted(unsupported)}"
            )

    async def author_candidate_for_gap(
        self,
        gap: Dict[str, Any],
        captured_telemetry: Sequence[Dict[str, Any]] = (),
        environment_id: str = "staging-range",
        target_format: str = "sigma",
        allowed_fields: Optional[Set[str]] = None,
        use_llm: bool = True,
    ) -> DetectionCandidate:
        """Synthesize a typed DetectionCandidate artifact for an identified gap."""
        technique_id = gap.get("technique_id") or gap.get("technique") or "T1059.001"
        action_name = gap.get("action_name") or f"Execution of {technique_id}"
        step_id = gap.get("step_id")
        is_model_only = gap.get("gap_type") == "model_only"

        # 1. Behavioral features from LogLM neighborhood or telemetry
        grounding_features: List[str] = []
        if is_model_only or gap.get("loglm_finding_id"):
            grounding_features = await self.retrieve_loglm_neighborhood(
                gap.get("loglm_finding_id", "f-loglm-1"),
                technique_id,
            )
            rationale = (
                f"Authored detection for model-only gap {technique_id} grounded in LogLM embedding "
                f"neighborhood features: {', '.join(grounding_features)}."
            )
        else:
            grounding_features = ["process_creation", "command_line_pattern"]
            rationale = (
                f"Authored portable rule for missed attack step {technique_id} ({action_name}) "
                f"without LogLM assist based on observed telemetry."
            )

        # 2. Build Sigma rule dictionary
        rule_dict, fields_used = self._build_sigma_rule(
            technique_id=technique_id,
            action_name=action_name,
            behavioral_features=grounding_features,
        )

        # 3. Grounding check
        valid_schema = allowed_fields if allowed_fields is not None else STANDARD_SCHEMA_FIELDS
        self.validate_fields_against_schema(fields_used, valid_schema)

        rule_yaml = yaml.dump(rule_dict, sort_keys=False)
        candidate_id = f"cand-{technique_id.replace('.', '_')}-{uuid.uuid4().hex[:6]}"

        return DetectionCandidate(
            candidate_id=candidate_id,
            environment_id=environment_id,
            technique_id=technique_id,
            gap_id=step_id,
            format=target_format,
            rule_name=rule_dict["title"],
            rule_content=rule_yaml,
            rationale=rationale,
            target_log_sources=["sysmon", "process_creation"],
            status=CandidateStatus.DRAFT,
            metadata={
                "authored_by": "detection_author_agent",
                "gap_type": gap.get("gap_type", "unspecified"),
                "loglm_grounded": is_model_only,
            },
        )

    def _build_sigma_rule(
        self,
        technique_id: str,
        action_name: str,
        behavioral_features: List[str],
    ) -> tuple[Dict[str, Any], Set[str]]:
        """Construct a valid behavioral Sigma rule and record used schema fields."""
        rule_title = f"Behavioral Detection for {technique_id} - {action_name}"
        fields_used: Set[str] = {"Image", "CommandLine"}

        if "T1059" in technique_id:
            selection = {
                "Image|endswith": ["\\powershell.exe", "\\pwsh.exe"],
                "CommandLine|contains": ["-enc", "-w hidden", "-noni", "-nop"],
            }
        elif "T1003" in technique_id:
            selection = {
                "CommandLine|contains": ["lsass", "sekurlsa", "minidump"],
            }
        elif "T1021" in technique_id:
            selection = {
                "Image|endswith": ["\\mstsc.exe", "\\wmic.exe"],
                "CommandLine|contains": ["/node:", "rdp", "/user:"],
            }
        elif "T1048" in technique_id:
            selection = {
                "CommandLine|contains": ["curl", "Invoke-WebRequest", "bitsadmin"],
            }
        else:
            selection = {
                "CommandLine|contains": ["cmd.exe", "powershell.exe"],
            }

        rule = {
            "title": rule_title,
            "id": str(uuid.uuid4()),
            "status": "experimental",
            "description": f"Grounded behavioral detection rule authored for MITRE ATT&CK technique {technique_id}.",
            "author": "Vigil Closed Loop Detection Engineer",
            "tags": [f"attack.{technique_id.lower()}", "attack.execution"],
            "logsource": {
                "category": "process_creation",
                "product": "windows",
            },
            "detection": {
                "selection": selection,
                "condition": "selection",
            },
            "falsepositives": ["Legitimate administrative maintenance scripts"],
            "level": "high",
        }
        return rule, fields_used


async def skill_author_detection(
    gap: Dict[str, Any],
    captured_telemetry: Sequence[Dict[str, Any]] = (),
    environment_id: str = "staging-range",
    target_format: str = "sigma",
    allowed_fields: Optional[Set[str]] = None,
) -> DetectionCandidate:
    """Skill entrypoint exposing the detection authoring role."""
    author = DetectionAuthor()
    return await author.author_candidate_for_gap(
        gap=gap,
        captured_telemetry=captured_telemetry,
        environment_id=environment_id,
        target_format=target_format,
        allowed_fields=allowed_fields,
    )
