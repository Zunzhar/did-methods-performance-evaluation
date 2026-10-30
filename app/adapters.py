"""Method-family adapter interface and local profile simulators.

The adapters intentionally model profile metadata and lifecycle assumptions only.
They are not real blockchain/DID-method clients.
"""
from dataclasses import dataclass
from typing import Any

from .config import PROFILES, ProfileSpec


@dataclass
class SimulatedDIDAdapter:
    spec: ProfileSpec
    visibility_override_ms: float | None = None

    @property
    def id(self) -> str:
        return self.spec.id

    @property
    def label(self) -> str:
        return self.spec.label

    def operation_cost(self, operation: str) -> float:
        return float(self.spec.synthetic_cost_units.get(operation, self.spec.synthetic_cost_units.get("resolve", 0.0)))

    def network_latency_assumption_ms(self) -> float:
        return float(self.spec.simulated_network_latency_ms)

    def visibility_delay_ms(self) -> float:
        if self.visibility_override_ms is not None:
            return max(0.0, float(self.visibility_override_ms))
        return float(self.spec.update_visibility_delay_ms)

    def normalize_event(self, *, operation: str, request_received_at: float,
                        method_accepted_at: float | None, publication_at: float | None,
                        finality_at: float | None, first_resolvable_at: float | None,
                        state_version: int | None, response_class: str,
                        metadata: dict[str, Any] | None = None) -> dict[str, Any]:
        """Return common event fields while preserving a profile id in metadata."""
        return {
            "profile": self.id,
            "operation": operation,
            "request_received_at": request_received_at,
            "method_accepted_at": method_accepted_at,
            "publication_at": publication_at,
            "finality_at": finality_at,
            "first_resolvable_at": first_resolvable_at,
            "state_version": state_version,
            "response_class": response_class,
            "metadata": {**(metadata or {}), "adapter": self.id, "simulated": True},
        }


class AdapterRegistry:
    def __init__(self, visibility_delay_overrides_ms: dict[str, float] | None = None):
        overrides = visibility_delay_overrides_ms or {}
        self._adapters = {
            profile_id: SimulatedDIDAdapter(PROFILES[profile_id], overrides.get(profile_id))
            for profile_id in PROFILES
        }

    def get(self, profile_id: str) -> SimulatedDIDAdapter:
        if profile_id not in self._adapters:
            raise ValueError(f"Unknown profile '{profile_id}'. Choose from: {', '.join(self._adapters)}")
        return self._adapters[profile_id]

    def all(self) -> list[SimulatedDIDAdapter]:
        return list(self._adapters.values())
