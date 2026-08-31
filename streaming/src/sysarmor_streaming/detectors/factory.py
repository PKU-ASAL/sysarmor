"""DetectorFactory: name -> constructor registry with a closed allow-list."""

from __future__ import annotations

from collections.abc import Sequence

from .contracts import Detector


class DetectorFactory:
    """Instantiates Detectors from a policy-declared name list.

    The registry maps ``name -> constructor`` (dict, not if/elif) because the
    Detector count keeps growing. Policy declares names declaratively; unknown
    names fail loudly here rather than being silently skipped.
    """

    _registry: dict[str, type[Detector]] = {}

    @classmethod
    def register(cls, named: dict[str, type[Detector]]) -> type[DetectorFactory]:
        cls._registry.update(named)
        return cls

    @classmethod
    def build(cls, names: Sequence[str]) -> list[Detector]:
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
