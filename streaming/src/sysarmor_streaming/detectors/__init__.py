"""Pluggable cloud-side Detector contract and factory."""

from .contracts import (
    AnalysisContext,
    Detector,
    DetectorInputs,
    DetectionResult,
    RequiredInput,
    StateRequirements,
)
from .factory import DetectorFactory

__all__ = [
    "AnalysisContext",
    "Detector",
    "DetectorFactory",
    "DetectorInputs",
    "DetectionResult",
    "RequiredInput",
    "StateRequirements",
]
