"""DetectorRegistry: name -> constructor registry with a closed allow-list."""

from __future__ import annotations

from collections.abc import Sequence

from .contracts import Detector, RequiredInput


class DetectorRegistry:
    """Instantiates Detectors from a policy-declared name list.

    The registry maps ``name -> constructor`` (dict, not if/elif) because the
    Detector count keeps growing. Policy declares names declaratively; unknown
    names fail loudly here rather than being silently skipped.
    """

    _registry: dict[str, type[Detector]] = {}

    @classmethod
    def register(cls, named: dict[str, type[Detector]]) -> type[DetectorRegistry]:
        cls._registry.update(named)
        return cls

    @classmethod
    def build(cls, names: Sequence[str] | None = None) -> list[Detector]:
        names = tuple(names) if names else tuple(sorted(cls._registry))
        detectors = []
        for name in names:
            constructor = cls._registry.get(name)
            if constructor is None:
                raise ValueError(
                    f"unknown detector {name!r}; registered: {sorted(cls._registry)}"
                )
            detectors.append(constructor())
        return detectors

    @classmethod
    def known(cls) -> frozenset[str]:
        return frozenset(cls._registry)

    @classmethod
    def affected_by(
        cls,
        changed_inputs: frozenset[RequiredInput],
        available_inputs: frozenset[RequiredInput] | None = None,
        available_signal_kinds: frozenset[int] | None = None,
    ) -> bool:
        return any(
            cls.detector_affected_by(
                constructor,
                changed_inputs,
                available_inputs,
                available_signal_kinds,
            )
            for constructor in cls._registry.values()
        )

    @staticmethod
    def detector_affected_by(
        detector,
        changed_inputs,
        available_inputs=None,
        available_signal_kinds=None,
    ) -> bool:
        required = frozenset(detector.required_inputs)
        return bool(
            changed_inputs.intersection(required)
            and DetectorRegistry.detector_inputs_available(
                detector, available_inputs, available_signal_kinds
            )
        )

    @classmethod
    def triggered_by(cls, changed_inputs, available_inputs=None, available_signal_kinds=None):
        return any(
            cls.detector_triggered_by(detector, changed_inputs, available_inputs, available_signal_kinds)
            for detector in cls._registry.values()
        )

    @staticmethod
    def detector_triggered_by(detector, changed_inputs, available_inputs=None, available_signal_kinds=None):
        required = frozenset(detector.required_inputs)
        default_triggers = (
            required - {RequiredInput.PROVENANCE_EDGE}
            if RequiredInput.SIGNAL in required
            else required
        )
        triggers = frozenset(getattr(detector, "trigger_inputs", default_triggers))
        return bool(
            changed_inputs.intersection(triggers)
            and DetectorRegistry.detector_inputs_available(detector, available_inputs, available_signal_kinds)
        )

    @staticmethod
    def detector_inputs_available(
        detector, available_inputs=None, available_signal_kinds=None
    ) -> bool:
        required = frozenset(detector.required_inputs)
        if available_inputs is not None and not required.issubset(available_inputs):
            return False
        accepted_kinds = getattr(detector, "signal_kinds", None)
        if accepted_kinds is None or available_signal_kinds is None:
            return True
        return bool(accepted_kinds.intersection(available_signal_kinds))
